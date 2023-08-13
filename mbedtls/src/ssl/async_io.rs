/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::{
    error::{codes, Error, Result},
    ssl::{
        context::Context,
        io::{IoCallback, IoCallbackUnsafe},
    },
};
use core::{
    result,
    task::{Context as TaskContext, Poll},
};
use futures::future;
use async_trait::async_trait;

#[cfg(all(feature = "std", feature = "async"))]
use std::{
    io::{Result as IoResult},
    pin::Pin,
};

#[cfg(all(feature = "std", feature = "async"))]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub trait AsyncIo {
    type Error;

    fn poll_recv(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<result::Result<usize, Self::Error>>;

    fn poll_send(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<result::Result<usize, Self::Error>>;
}

#[derive(Copy, Clone, Debug)]
pub enum ClosedError<E> {
    Other(E),
    Closed,
}

impl<E> From<E> for ClosedError<E> {
    fn from(err: E) -> Self {
        Self::Other(err)
    }
}

#[async_trait(?Send)]
pub trait AsyncIoExt: AsyncIo {
    async fn recv(&mut self, buf: &mut [u8]) -> result::Result<usize, Self::Error> {
        future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    async fn recv_exact(&mut self, buf: &mut [u8]) -> result::Result<(), ClosedError<Self::Error>> {
        let mut pos = 0;
        while pos < buf.len() {
            let n = self.recv(&mut buf[pos..]).await?;
            if n == 0 {
                return Err(ClosedError::Closed);
            }
            pos += n;
        }
        assert_eq!(pos, buf.len());
        Ok(())
    }

    async fn send(&mut self, buf: &[u8]) -> result::Result<usize, Self::Error> {
        future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    async fn send_all(&mut self, buf: &[u8]) -> result::Result<(), ClosedError<Self::Error>> {
        let mut pos = 0;
        while pos < buf.len() {
            let n = self.send(&buf[pos..]).await?;
            if n == 0 {
                return Err(ClosedError::Closed);
            }
            pos += n;
        }
        assert_eq!(pos, buf.len());
        Ok(())
    }
}

impl<T: AsyncIo + ?Sized> AsyncIoExt for T {}

pub enum AnyAsyncIo {}

impl<'a, 'b, 'c, IO: AsyncIo + core::marker::Unpin + 'static> IoCallback<AnyAsyncIo>
    for (&'a mut TaskContext<'b>, &'c mut IO)
{
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.1.poll_recv(self.0, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(codes::NetRecvFailed.into()),
            Poll::Pending => Err(codes::SslWantRead.into()),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        match self.1.poll_send(self.0, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(_)) => Err(codes::NetSendFailed.into()),
            Poll::Pending => Err(codes::SslWantWrite.into()),
        }
    }
}

/// Marker type for an IO implementation that implements both
/// `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.
#[cfg(all(feature = "std", feature = "async"))]
pub enum AsyncStream {}

#[cfg(all(feature = "std", feature = "async"))]
impl<'a, 'b, 'c, IO: AsyncRead + AsyncWrite + std::marker::Unpin + 'static> IoCallback<AsyncStream>
    for (&'a mut TaskContext<'b>, &'c mut IO)
{
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buf = ReadBuf::new(buf);
        let io = Pin::new(&mut self.1);
        match io.poll_read(self.0, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(_)) => Err(codes::NetRecvFailed.into()),
            Poll::Pending => Err(codes::SslWantRead.into()),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let io = Pin::new(&mut self.1);
        match io.poll_write(self.0, buf) {
            Poll::Ready(Err(_)) => Err(codes::NetSendFailed.into()),
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Pending => Err(codes::SslWantWrite.into()),
        }
    }
}

impl<T> Context<T> {
    pub async fn establish_async<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.prepare_handshake(io, hostname)?;

        future::poll_fn(|cx| self.poll_handshake_inner(cx)).await
    }

    pub async fn recv_async<IoType>(&mut self, buf: &mut [u8]) -> Result<usize>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        future::poll_fn(|cx| self.poll_recv_inner(cx, buf)).await
    }

    pub async fn send_async<IoType>(&mut self, buf: &[u8]) -> Result<usize>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        future::poll_fn(|cx| self.poll_send_inner(cx, buf)).await
    }

    pub async fn flush_async<IoType>(&mut self) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        future::poll_fn(|cx| self.poll_flush_inner(cx)).await
    }

    pub async fn close_async<IoType>(&mut self) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        future::poll_fn(|cx| self.poll_close_inner(cx)).await
    }

    fn poll_handshake_inner<IoType>(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<()>>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.with_bio_async(cx, |ssl_ctx| match ssl_ctx.handshake() {
            Err(e)
                if matches!(
                    e.high_level(),
                    Some(codes::SslWantRead | codes::SslWantWrite)
                ) =>
            {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
            Ok(()) => Poll::Ready(Ok(())),
        })
        .unwrap_or(Poll::Ready(Err(codes::NetSendFailed.into())))
    }

    fn poll_recv_inner<IoType>(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.ensure_stream_still_open()?;

        self.with_bio_async(cx, |ssl_ctx| match ssl_ctx.read_impl_inner(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.high_level() == Some(codes::SslWantRead) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        })
        .unwrap_or_else(|| Poll::Ready(Err(codes::NetRecvFailed.into())))
    }

    fn poll_send_inner<IoType>(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.ensure_stream_still_open()?;

        self.with_bio_async(cx, |ssl_ctx| match ssl_ctx.async_write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.high_level() == Some(codes::SslPeerCloseNotify) => Poll::Ready(Ok(0)),
            Err(e) if e.high_level() == Some(codes::SslWantWrite) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        })
        .unwrap_or_else(|| Poll::Ready(Err(codes::NetSendFailed.into())))
    }

    fn poll_flush_inner<IoType>(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<()>>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.ensure_stream_still_open()?;

        self.with_bio_async(cx, |ssl_ctx| match ssl_ctx.flush_output() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.high_level() == Some(codes::SslWantWrite) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        })
        .unwrap_or_else(|| Poll::Ready(Err(codes::NetSendFailed.into())))
    }

    fn poll_close_inner<IoType>(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<()>>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        self.ensure_stream_still_open()?;

        self.with_bio_async(cx, |ssl_ctx| match ssl_ctx.close_notify() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e)
                if matches!(
                    e.high_level(),
                    Some(codes::SslWantRead | codes::SslWantWrite)
                ) =>
            {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
        .unwrap_or_else(|| Poll::Ready(Err(codes::NetSendFailed.into())))
    }

    fn ensure_stream_still_open(&self) -> Result<()> {
        if self.handle().private_session.is_null() {
            Err(codes::NetInvalidContext.into())
        } else {
            Ok(())
        }
    }
}

impl<T: AsyncIo> AsyncIo for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AnyAsyncIo>,
{
    type Error = Error;

    fn poll_recv(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<result::Result<usize, Self::Error>> {
        self.poll_recv_inner(cx, buf)
    }

    fn poll_send(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<result::Result<usize, Self::Error>> {
        self.poll_send_inner(cx, buf)
    }
}

#[cfg(all(feature = "std", feature = "async"))]
impl<T: AsyncRead> AsyncRead for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let poll = poll_to_poll_io(self.poll_recv_inner(cx, buf.initialize_unfilled()));
        poll.map(|r| r.map(|n| buf.advance(n)))
    }
}

#[cfg(all(feature = "std", feature = "async"))]
impl<T: AsyncWrite + Unpin> AsyncWrite for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        poll_to_poll_io(self.poll_send_inner(cx, buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        poll_to_poll_io(self.poll_flush_inner(cx))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        poll_to_poll_io(self.poll_close_inner(cx)).map(|r| {
            // preserve old behavior
            self.drop_io();
            r
        })
    }
}

#[cfg(all(feature = "std", feature = "async"))]
fn poll_to_poll_io<T>(poll: Poll<Result<T>>) -> Poll<IoResult<T>> {
    poll.map(|r| r.map_err(crate::private::error_to_io_error))
}

// TODO: AsyncIo impl for tokio::net::UdpSocket
