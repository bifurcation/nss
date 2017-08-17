/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * TLS 1.3 Transaction Framing
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ssl.h"
#include "sslimpl.h"
#include "sslproto.h"

#define IO_BUFFER_SIZE (1 << 16)

typedef struct {
  uint8_t r[IO_BUFFER_SIZE];
  uint8_t w[IO_BUFFER_SIZE];
  int32_t r_start;
  int32_t r_end;
  int32_t w_start;
} buffer_t;

static void buffer_clear(buffer_t *buffer) {
  PORT_Memset(buffer->r, 0, IO_BUFFER_SIZE);
  PORT_Memset(buffer->w, 0, IO_BUFFER_SIZE);
  buffer->r_start = 0;
  buffer->r_end = 0;
  buffer->w_start = 0;
}

static PRStatus buffer_close(PRFileDesc *f) {
  buffer_t *buffer = (buffer_t *) f->secret;

  f->secret = NULL;
  free(buffer);
  return PR_SUCCESS;
}

static PRStatus buffer_read(PRFileDesc *f, void *buf, int32_t length) {
  buffer_t *buffer = (buffer_t *) f->secret;

  if (buffer->r_end - buffer->r_start < length) {
    return PR_WOULD_BLOCK_ERROR;
  }

  PORT_Memcpy(buf, buffer->r + buffer->r_start, length);
  buffer->r_start += length;
  return PR_SUCCESS;
}

static PRStatus buffer_write(PRFileDesc *f, const void *buf, int32_t length) {
  buffer_t *buffer = (buffer_t *) f->secret;

  if (buffer->w_start + length > IO_BUFFER_SIZE) {
    return PR_WOULD_BLOCK_ERROR;
  }

  PORT_Memcpy(buffer->w + buffer->w_start, buf, length);
  buffer->w_start += length;
  return PR_SUCCESS;
}

static int32_t buffer_recv(PRFileDesc *f, void *buf, int32_t length,
                           PRIntn flags, PRIntervalTime timeout) {
  buffer_t *buffer = (buffer_t *) f->secret;

  if (flags != 0) {
    return PR_INVALID_ARGUMENT_ERROR;
  }

  int32_t to_send = length;
  if (buffer->r_end - buffer->r_start < length) {
    to_send = buffer->r_end - buffer->r_start;
  }

  PORT_Memcpy(buf, buffer->r + buffer->r_start, to_send);
  buffer->r_start += to_send;
  return to_send;
}

static int32_t buffer_send(PRFileDesc *f, const void *buf, int32_t length,
                           PRIntn flags, PRIntervalTime timeout) {
  buffer_t *buffer = (buffer_t *) f->secret;

  if (flags != 0) {
    return PR_INVALID_ARGUMENT_ERROR;
  }

  int32_t to_send = length;
  if (buffer->w_start + length > IO_BUFFER_SIZE) {
    to_send = IO_BUFFER_SIZE - buffer->w_start;
  }

  PORT_Memcpy(buffer->w + buffer->w_start, buf, to_send);
  buffer->w_start += to_send;
  return to_send;
}

static PRStatus buffer_getpeername(PRFileDesc *fd, PRNetAddr *addr) {
  addr->inet.family = PR_AF_INET;
  addr->inet.port = 0;
  addr->inet.ip = 0;
  return PR_SUCCESS;
}

static PRStatus buffer_getsockopt(PRFileDesc *fd, PRSocketOptionData *data) {
  if (data->option == PR_SockOpt_Nonblocking) {
    data->value.non_blocking = PR_TRUE;
    return PR_SUCCESS;
  }

  return PR_FAILURE;
}

const struct PRIOMethods recorder_methods = {
  PR_DESC_LAYERED,
  buffer_close,       // Close
  buffer_read,        // Read
  buffer_write,       // Write
  NULL,               // Available         NOT USED
  NULL,               // Available64       NOT USED
  NULL,               // Sync              NOT USED
  NULL,               // Seek              NOT USED
  NULL,               // Seek64            NOT USED
  NULL,               // FileInfo          NOT USED
  NULL,               // FileInfo64        NOT USED
  NULL,               // Writev            NOT USED
  NULL,               // Connect           NOT USED
  NULL,               // Accept            NOT USED
  NULL,               // Bind              NOT USED
  NULL,               // Listen            NOT USED
  NULL,               // Shutdown          NOT USED
  buffer_recv,        // Recv
  buffer_send,        // Send
  NULL,               // Recvfrom          NOT USED
  NULL,               // Sendto            NOT USED
  NULL,               // Poll              NOT USED
  NULL,               // AcceptRead        NOT USED
  NULL,               // TransmitFile      NOT USED
  NULL,               // Getsockname       NOT USED
  buffer_getpeername, // Getpeername       NOT USED
  NULL,               // Reserved
  NULL,               // Reserved
  buffer_getsockopt,  // Getsockoption
  NULL,               // Setsockoption     NOT USED (?)
  NULL,               // Sendfile          NOT USED
  NULL,               // ConnectContinue   NOT USED
  NULL,               // Reserved
  NULL,               // Reserved
  NULL,               // Reserved
  NULL,               // Reserved
};

PRFileDesc
*TLSTXN_Create()
{
  /* Create the buffer for message I/O */
  PRDescIdentity id = PR_GetUniqueIdentity("tls_txn");
  buffer_t *buffer = (buffer_t *) malloc(sizeof(buffer_t));
  if (!buffer) {
    return NULL;
  }

  buffer_clear(buffer);

  /* Wrap the buffer in a file descriptor */
  PRFileDesc *base_fd = PR_CreateIOLayerStub(id, &recorder_methods);
  if (!base_fd) {
    return NULL;
  }

  base_fd->secret = (PRFilePrivate *) buffer;

  /* Set up the file descriptor for TLS 1.3 */
  PRFileDesc *ssl_fd = SSL_ImportFD(NULL, base_fd);
  if (!ssl_fd) {
    PR_Close(base_fd);
    return NULL;
  }

  SSLVersionRange version_range = {
    SSL_LIBRARY_VERSION_TLS_1_3,
    SSL_LIBRARY_VERSION_TLS_1_3
  };

  if (SSL_VersionRangeSet(ssl_fd, &version_range) != SECSuccess) {
    PR_Close(ssl_fd);
    return NULL;
  }

  return ssl_fd;
}

SECStatus
TLSTXN_CreateClientHello(PRFileDesc* client_socket, SECItem *client_hello)
{
  SECStatus rv;

  sslSocket *ss = (sslSocket *) client_socket->secret;
  buffer_t *buffer = (buffer_t *) client_socket->lower->secret;

  buffer_clear(buffer);

  /* Trigger the client to begin the handshake */
  ssl_Get1stHandshakeLock(ss)

  rv = ssl_BeginClientHandshake(ss);
  if (rv != SECSuccess) {
    return rv;
  }

  ssl_Release1stHandshakeLock(ss);

  /* At this point, the buffer should contain a ClientHello message */
  client_hello->len = buffer->w_start;
  client_hello->data = PORT_Alloc(client_hello->len);
  PORT_Memcpy(client_hello->data, buffer->w, client_hello->len);
  return SECSuccess;
}

SECStatus
TLSTXN_HandleClientHello(PRFileDesc* server_socket,
                         SECItem *client_hello,
                         SECItem *server_first_flight)
{
  SECStatus rv;

  sslSocket *ss = (sslSocket *) server_socket->secret;
  buffer_t *buffer = (buffer_t *) server_socket->lower->secret;

  buffer_clear(buffer);

  /* Copy the ClientHello into the read buffer */
  if (client_hello->len > IO_BUFFER_SIZE) {
    PORT_SetError(PR_INVALID_ARGUMENT_ERROR);
    return SECFailure;
  }

  memcpy(buffer->r, client_hello->data, client_hello->len);
  buffer->r_end = client_hello->len;


  /* Trigger the server to process the ClientHello */
  rv = ssl_BeginServerHandshake(ss);
  if (rv != SECSuccess) {
    return rv;
  }

  ssl_Get1stHandshakeLock(ss)
  rv = ssl_Do1stHandshake(ss);
  ssl_Release1stHandshakeLock(ss);

  if (rv != SECSuccess) {
    /*
     * PR_WOULD_BLOCK_ERROR and PR_END_OF_FILE_ERROR just indicates the
     * handshake ran out of records to process, which we expect, because we
     * only gave it a ClientHello.
     */
    PRErrorCode err = PR_GetError();
    if ((err != PR_WOULD_BLOCK_ERROR) &&
        (err != PR_END_OF_FILE_ERROR)) {
      return rv;
    }
  }

  /* At this point, the buffer contains the server's first flight */
  server_first_flight->len = buffer->w_start;
  server_first_flight->data = PORT_Alloc(server_first_flight->len);
  PORT_Memcpy(server_first_flight->data, buffer->w, server_first_flight->len);
  return SECSuccess;
}

SECStatus
TLSTXN_HandleServerFirstFlight(PRFileDesc* client_socket,
                               SECItem *server_first_flight,
                               SECItem *client_second_flight)
{
  SECStatus rv;

  sslSocket *ss = (sslSocket *) client_socket->secret;
  buffer_t *buffer = (buffer_t *) client_socket->lower->secret;

  buffer_clear(buffer);

  /* Copy the server's flight into the read buffer */
  if (server_first_flight->len > IO_BUFFER_SIZE) {
    PORT_SetError(PR_INVALID_ARGUMENT_ERROR);
    return SECFailure;
  }

  memcpy(buffer->r, server_first_flight->data, server_first_flight->len);
  buffer->r_end = server_first_flight->len;


  /* Trigger the server to process the flight */
  ssl_Get1stHandshakeLock(ss)
  rv = ssl_Do1stHandshake(ss);
  ssl_Release1stHandshakeLock(ss);

  if (rv != SECSuccess) {
    return rv;
  }

  /* At this point, the buffer contains the client's second flight */
  client_second_flight->len = buffer->w_start;
  client_second_flight->data = PORT_Alloc(client_second_flight->len);
  PORT_Memcpy(client_second_flight->data, buffer->w, client_second_flight->len);
  return SECSuccess;
}

SECStatus
TLSTXN_HandleClientSecondFlight(PRFileDesc* server_socket,
                                SECItem *client_second_flight)
{
  SECStatus rv;

  sslSocket *ss = (sslSocket *) server_socket->secret;
  buffer_t *buffer = (buffer_t *) server_socket->lower->secret;

  buffer_clear(buffer);

  /* Copy the server's flight into the read buffer */
  if (client_second_flight->len > IO_BUFFER_SIZE) {
    PORT_SetError(PR_INVALID_ARGUMENT_ERROR);
    return SECFailure;
  }

  memcpy(buffer->r, client_second_flight->data, client_second_flight->len);
  buffer->r_end = client_second_flight->len;


  /* Trigger the server to process the flight */
  ssl_Get1stHandshakeLock(ss)
  rv = ssl_Do1stHandshake(ss);
  ssl_Release1stHandshakeLock(ss);

  return rv;
}

SECStatus
TLSTXN_Protect(PRFileDesc* socket, SECItem *ciphertext, SECItem *plaintext)
{
  buffer_t *buffer = (buffer_t *) socket->lower->secret;
  buffer_clear(buffer);

  /* Trigger encryption with a send */
  int32_t sent = PR_Send(socket, plaintext->data, plaintext->len, 0, PR_INTERVAL_NO_TIMEOUT);
  if (sent < plaintext->len) {
    return SECFailure;
  }

  /* Read the ciphertext out of the write buffer */
  ciphertext->len = buffer->w_start;
  ciphertext->data = PORT_Alloc(ciphertext->len);
  PORT_Memcpy(ciphertext->data, buffer->w, ciphertext->len);

  return SECSuccess;
}

SECStatus
TLSTXN_Unprotect(PRFileDesc* socket, SECItem *plaintext, SECItem *ciphertext)
{
  /* Position the ciphertext in the read buffer */
  buffer_t *buffer = (buffer_t *) socket->lower->secret;
  buffer_clear(buffer);

  if (ciphertext->len > IO_BUFFER_SIZE) {
    PORT_SetError(PR_INVALID_ARGUMENT_ERROR);
    return SECFailure;
  }

  memcpy(buffer->r, ciphertext->data, ciphertext->len);
  buffer->r_end = ciphertext->len;


  /* Trigger decryption with a recv */
  plaintext->len = ciphertext->len;
  plaintext->data = PORT_Alloc(plaintext->len);

  int32_t read = PR_Recv(socket, plaintext->data, plaintext->len, 0, PR_INTERVAL_NO_TIMEOUT);
  if (read < 0) {
    return SECFailure;
  }

  plaintext->len = read;
  return SECSuccess;
}
