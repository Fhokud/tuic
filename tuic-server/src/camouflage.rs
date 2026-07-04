use std::{io, sync::Arc};

use axum::http::{
	HeaderName, Request, Response, Uri,
	header::{HOST, HeaderValue},
};
use bytes::{Buf, Bytes};
use futures_util::{StreamExt, TryStreamExt, stream};
use h3::server;
use reqwest::{Body, Client, Method, Url};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, info, warn};
use tuic_core::quinn::QuinnConnection;

use crate::{AppContext, config::CamouflageConfig};

const RESPONSE_DATA_CHUNK_SIZE: usize = 64 * 1024;

pub async fn handle(
	ctx: Arc<AppContext>,
	conn: QuinnConnection,
	prefetched_uni: Option<crate::h3_quinn_compat::PeekableRecvStream>,
	prefetched_bi: Option<crate::h3_quinn_compat::PrefetchedBiRecv>,
) -> eyre::Result<()> {
	let Some(camouflage) = ctx.cfg.camouflage.as_ref().filter(|cfg| cfg.enabled) else {
		return Ok(());
	};

	let (backend, backend_host_override, idle_timeout, client) = build_backend_route(camouflage)?;

	info!(
		id = conn.stable_id() as u32,
		addr = %conn.remote_address(),
		"HTTP/3 camouflage enabled, reverse proxy target={target}, backend_host={host:?}",
		target = backend,
		host = backend_host_override
	);

	let quic_conn = crate::h3_quinn_compat::Connection::new_with_prefetched(conn, prefetched_uni, prefetched_bi);
	let mut h3_conn = server::Connection::new(quic_conn).await?;
	let mut requests = JoinSet::new();

	while let Some(resolver) = h3_conn.accept().await? {
		let (request, stream) = resolver.resolve_request().await?;
		debug!(
			"[camouflage] incoming h3 request: method={} uri={}",
			request.method(),
			request.uri()
		);

		let client = client.clone();
		let backend = backend.clone();
		let backend_host_override = backend_host_override.clone();
		requests.spawn(async move {
			if let Err(err) = forward_request(
				&client,
				&backend,
				backend_host_override.as_deref(),
				idle_timeout,
				request,
				stream,
			)
			.await
			{
				warn!("[camouflage] request forwarding failed: {err}");
			}
		});
	}

	while let Some(result) = requests.join_next().await {
		if let Err(err) = result {
			warn!("[camouflage] request forwarding task failed: {err}");
		}
	}

	Ok(())
}

fn build_backend_route(camouflage: &CamouflageConfig) -> eyre::Result<(Url, Option<String>, std::time::Duration, Client)> {
	let mut backend = Url::parse(camouflage.reverse_proxy_url.as_str())?;
	let backend_host = backend
		.host_str()
		.ok_or_else(|| eyre::eyre!("`camouflage.reverse_proxy_url` must contain a host"))?
		.to_string();
	let backend_port = backend
		.port_or_known_default()
		.ok_or_else(|| eyre::eyre!("`camouflage.reverse_proxy_url` has no known port"))?;

	let mut client_builder = Client::builder()
		.danger_accept_invalid_certs(camouflage.skip_backend_tls_verify)
		.pool_max_idle_per_host(0);
	let mut backend_host_override = camouflage.reverse_proxy_hostname.clone();

	if let Some(reverse_proxy_hostname) = camouflage.reverse_proxy_hostname.as_deref() {
		backend
			.set_host(Some(reverse_proxy_hostname))
			.map_err(|_| eyre::eyre!("invalid `camouflage.reverse_proxy_hostname`: {reverse_proxy_hostname}"))?;
		if let Ok(ip) = backend_host.parse::<std::net::IpAddr>() {
			client_builder = client_builder.resolve(reverse_proxy_hostname, std::net::SocketAddr::new(ip, backend_port));
		}
		backend_host_override = Some(reverse_proxy_hostname.to_string());
	}

	let client = client_builder.build()?;
	Ok((backend, backend_host_override, camouflage.request_timeout, client))
}

async fn forward_request<S>(
	client: &Client,
	backend: &Url,
	backend_host_override: Option<&str>,
	idle_timeout: std::time::Duration,
	request: Request<()>,
	stream: server::RequestStream<S, Bytes>,
) -> eyre::Result<()>
where
	S: h3::quic::BidiStream<Bytes> + Send + 'static,
	S::SendStream: Send + 'static,
	S::RecvStream: Send + 'static,
{
	let (mut response_stream, mut request_stream) = stream.split();
	let target = rewrite_target_url(backend, request.uri())?;
	let method = Method::from_bytes(request.method().as_str().as_bytes())?;
	let mut backend_request = client.request(method, target);

	for (name, value) in request.headers() {
		if is_forwardable_header(name) {
			backend_request = backend_request.header(name, value);
		}
	}
	if let Some(host) = backend_host_override {
		backend_request = backend_request.header(HOST, host);
	} else if let Some(host) = request
		.headers()
		.get(HOST)
		.and_then(|h| HeaderValue::from_bytes(h.as_bytes()).ok())
	{
		backend_request = backend_request.header(HOST, host);
	}

	if let Some(first_chunk) = read_request_body_chunk(&mut request_stream, idle_timeout).await? {
		let body_stream = request_body_stream(first_chunk, request_stream, idle_timeout);
		backend_request = backend_request.body(Body::wrap_stream(body_stream));
	}

	let backend_response = match backend_request.send().await {
		Ok(response) => response,
		Err(err) => {
			let resp = Response::builder().status(502).body(())?;
			_ = response_stream.send_response(resp).await;
			_ = response_stream.finish().await;
			return Err(err.into());
		}
	};
	let status = backend_response.status();
	let headers = backend_response.headers().clone();

	let mut response = Response::builder().status(status);
	for (name, value) in &headers {
		if is_forwardable_header(name) {
			response = response.header(name, value);
		}
	}
	let response = response.body(())?;
	response_stream.send_response(response).await?;

	let mut body_stream = backend_response.bytes_stream().map_err(io::Error::other);
	while let Some(chunk) = recv_stream_item_with_idle_timeout(&mut body_stream, idle_timeout).await? {
		if !chunk.is_empty() {
			send_response_data_with_idle_timeout(&mut response_stream, chunk, idle_timeout).await?;
		}
	}
	finish_response_with_idle_timeout(&mut response_stream, idle_timeout).await?;
	Ok(())
}

async fn read_request_body_chunk<S>(
	stream: &mut server::RequestStream<S, Bytes>,
	idle_timeout: std::time::Duration,
) -> eyre::Result<Option<Bytes>>
where
	S: h3::quic::RecvStream,
{
	if let Some(mut chunk) = recv_data_with_idle_timeout(stream, idle_timeout).await? {
		let remaining = chunk.remaining();
		return Ok(Some(chunk.copy_to_bytes(remaining)));
	}

	let _ = recv_trailers_with_idle_timeout(stream, idle_timeout).await?;
	Ok(None)
}

fn request_body_stream<S>(
	first_chunk: Bytes,
	stream: server::RequestStream<S, Bytes>,
	idle_timeout: std::time::Duration,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
	S: h3::quic::RecvStream + Send + 'static,
{
	let (tx, rx) = mpsc::channel(16);
	tokio::spawn(async move {
		let mut stream = stream;
		if tx.send(Ok(first_chunk)).await.is_err() {
			return;
		}
		loop {
			match read_request_body_chunk(&mut stream, idle_timeout).await {
				Ok(Some(chunk)) => {
					if tx.send(Ok(chunk)).await.is_err() {
						break;
					}
				}
				Ok(None) => break,
				Err(err) => {
					_ = tx.send(Err(io::Error::other(err))).await;
					break;
				}
			}
		}
	});
	stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) })
}

async fn recv_data_with_idle_timeout<S>(
	stream: &mut server::RequestStream<S, Bytes>,
	idle_timeout: std::time::Duration,
) -> eyre::Result<Option<impl Buf>>
where
	S: h3::quic::RecvStream,
{
	Ok(tokio::time::timeout(idle_timeout, stream.recv_data()).await??)
}

async fn recv_trailers_with_idle_timeout<S>(
	stream: &mut server::RequestStream<S, Bytes>,
	idle_timeout: std::time::Duration,
) -> eyre::Result<Option<axum::http::HeaderMap>>
where
	S: h3::quic::RecvStream,
{
	Ok(tokio::time::timeout(idle_timeout, stream.recv_trailers()).await??)
}

async fn recv_stream_item_with_idle_timeout<S, T>(stream: &mut S, idle_timeout: std::time::Duration) -> eyre::Result<Option<T>>
where
	S: futures_util::Stream<Item = Result<T, io::Error>> + Unpin,
{
	Ok(tokio::time::timeout(idle_timeout, stream.next()).await?.transpose()?)
}

async fn send_response_data_with_idle_timeout<S>(
	stream: &mut server::RequestStream<S, Bytes>,
	mut chunk: Bytes,
	idle_timeout: std::time::Duration,
) -> eyre::Result<()>
where
	S: h3::quic::SendStream<Bytes>,
{
	while !chunk.is_empty() {
		let len = chunk.len().min(RESPONSE_DATA_CHUNK_SIZE);
		let data = chunk.split_to(len);
		tokio::time::timeout(idle_timeout, stream.send_data(data)).await??;
	}
	Ok(())
}

async fn finish_response_with_idle_timeout<S>(
	stream: &mut server::RequestStream<S, Bytes>,
	idle_timeout: std::time::Duration,
) -> eyre::Result<()>
where
	S: h3::quic::SendStream<Bytes>,
{
	Ok(tokio::time::timeout(idle_timeout, stream.finish()).await??)
}

fn rewrite_target_url(backend: &Url, uri: &Uri) -> eyre::Result<Url> {
	let mut target = backend.clone();
	let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
	target.set_path("");
	target.set_query(None);
	let target = target.join(path_and_query)?;
	Ok(target)
}

fn is_forwardable_header(name: &HeaderName) -> bool {
	!matches!(
		name.as_str().to_ascii_lowercase().as_str(),
		"connection"
			| "keep-alive"
			| "proxy-connection"
			| "transfer-encoding"
			| "upgrade"
			| "te" | "trailer"
			| "host" | "content-length"
	)
}
