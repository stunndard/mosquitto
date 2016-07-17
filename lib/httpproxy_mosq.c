/*
Copyright (c) 2014 Roger Light <roger@atchoo.org>
Copyright (c) 2016 Roman Butusov <reaxis@mail.ru>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
   Roman Butusov - HTTP proxy support
*/

#include <errno.h>
#include <string.h>

#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "send_mosq.h"

#define BASE64_SIZE(x) (((x)+2) / 3 * 4 + 1)

#ifdef WITH_HTTP_PROXY
int memmem(uint8_t *haystack, size_t hlen, uint8_t *needle, size_t nlen) {
    if (nlen == 0) return 1; /* degenerate edge case */
    if (hlen < nlen) return 1; /* another degenerate edge case */
    uint8_t *hlimit = haystack + hlen - nlen + 1;
    while ((haystack = memchr(haystack, needle[0], hlimit-haystack))) {
        if (!memcmp(haystack, needle, nlen)) return 1;
        haystack++;
    }
    return 0;
}

char *base64_encode(char *out, int out_size, const uint8_t *in, int in_size)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *ret, *dst;
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_size;

    if (in_size >= 90000 / 4 ||
        out_size < BASE64_SIZE(in_size))
        return NULL;
    ret = dst = out;
    while (bytes_remaining) {
        i_bits = (i_bits << 8) + *in++;
        bytes_remaining--;
        i_shift += 8;

        do {
            *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
            i_shift -= 6;
        } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
    }
    while ((dst - ret) & 3)
        *dst++ = '=';
    *dst = '\0';

    return ret;
}

char* basic_authentication_encode(const char *user, const char *passwd)
{
    /* prepare the user:pass key pair */
    //printf("passwd: %d\r\n", passwd);
    int pair_len = strlen(user) + 1;
    if(passwd){
	pair_len += strlen(passwd);
    }
    char pair[pair_len + 1];

    sprintf(pair, "%s:%s", user, passwd);

    /* calculate the final string length */
    int basic_len = BASE64_SIZE(pair_len);
    char *basic_ptr = _mosquitto_calloc(1, basic_len + 1);

    if (!base64_encode(basic_ptr, basic_len, (const uint8_t*)pair, pair_len))
	return NULL;

    return basic_ptr;
}
#endif

int mosquitto_httpproxy_set(struct mosquitto *mosq, const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_HTTP_PROXY
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || strlen(host) > 256) return MOSQ_ERR_INVAL;
	if(port < 1 || port > 65535) return MOSQ_ERR_INVAL;

	if(mosq->httpproxy_host){
		_mosquitto_free(mosq->httpproxy_host);
	}

	if(mosq->socks5_host){
		_mosquitto_free(mosq->socks5_host);
		mosq->socks5_host = NULL;
	}

	mosq->httpproxy_host = _mosquitto_strdup(host);
	if(!mosq->httpproxy_host){
		return MOSQ_ERR_NOMEM;
	}

	mosq->httpproxy_port = port;

	if(mosq->httpproxy_username){
		_mosquitto_free(mosq->httpproxy_username);
	}
	if(mosq->httpproxy_password){
		_mosquitto_free(mosq->httpproxy_password);
	}

	if(username){
		mosq->httpproxy_username = _mosquitto_strdup(username);
		if(!mosq->httpproxy_username){
			return MOSQ_ERR_NOMEM;
		}

		if(password){
			mosq->httpproxy_password = _mosquitto_strdup(password);
			if(!mosq->httpproxy_password){
				_mosquitto_free(mosq->httpproxy_username);
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	//printf("httpproxy_set done\r\n");
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

#ifdef WITH_HTTP_PROXY
int mosquitto__httpproxy_send(struct mosquitto *mosq)
{
	struct _mosquitto_packet *packet;
	int len1, len2;
	int ulen;
	char *head1 = "CONNECT %s:%d HTTP/1.0\r\n";
	char *head2 = "Proxy-Authorization: Basic %s\r\n";
	char *header1, *header2;
	char *secret;

	if(mosq->state == mosq_cs_httpproxy_new){
                packet = _mosquitto_calloc(1, sizeof(struct _mosquitto_packet));
                if(!packet) return MOSQ_ERR_NOMEM;

		if(mosq->httpproxy_username){
		    secret = basic_authentication_encode(mosq->httpproxy_username, mosq->httpproxy_password);
		    //printf("secret: %s\r\n", secret);
		    len1 = snprintf(NULL, 0, head1, mosq->host, mosq->port);
		    len2 = snprintf(NULL, 0, head2, secret);
		    ulen = len1 + len2 + 2;

		    header1 = _mosquitto_calloc(1, ulen + 1);
		    if(!header1) return MOSQ_ERR_NOMEM;
		    header2 = _mosquitto_calloc(1, len2);
		    if(!header2) return MOSQ_ERR_NOMEM;
		    
		    snprintf(header1, ulen, head1, mosq->host, mosq->port);
		    snprintf(header2, ulen, head2, secret);
		    strncat(header1, header2, len2);
		    _mosquitto_free(secret);
		    _mosquitto_free(header2);
		}else{
		    ulen = snprintf(NULL, 0, head1, mosq->host, mosq->port);
		    ulen += 2;
		    header1 = _mosquitto_calloc(1, ulen + 1);
		    if(!header1) return MOSQ_ERR_NOMEM;
		    snprintf(header1, ulen, head1, mosq->host, mosq->port);
		}
		strncat(header1, "\r\n", 2);
		//printf("header len= %d\r\n", ulen);
		//printf("%s\r\n", header);

        	packet->packet_length = ulen;
                packet->payload = _mosquitto_malloc(sizeof(uint8_t)*packet->packet_length);
		if (!packet->payload){
		    _mosquitto_free(header1);
		    _mosquitto_free(packet);
		    return MOSQ_ERR_NOMEM;
		}

                memcpy(&(packet->payload[0]), header1, ulen);
		_mosquitto_free(header1);

                pthread_mutex_lock(&mosq->state_mutex);
                mosq->state = mosq_cs_httpproxy_start;
                pthread_mutex_unlock(&mosq->state_mutex);

                mosq->in_packet.pos = 0;
                mosq->in_packet.packet_length = 12; // HTTP/1.0 200
                mosq->in_packet.to_process = 12;
                mosq->in_packet.payload = _mosquitto_malloc(sizeof(uint8_t)*12);
                if(!mosq->in_packet.payload){
                        _mosquitto_free(packet->payload);
                        _mosquitto_free(packet);
                        return MOSQ_ERR_NOMEM;
                }
		//printf("headers sent\r\n");
                return _mosquitto_packet_queue(mosq, packet);
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto__httpproxy_read(struct mosquitto *mosq)
{
	ssize_t len;
	uint8_t *payload;
	int rc;
	char resp[4];

        if(mosq->state == mosq_cs_httpproxy_start){
		//printf("processing\r\n");
                while(mosq->in_packet.to_process > 0){
                        len = _mosquitto_net_read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
                        if(len > 0){
                                mosq->in_packet.pos += len;
                                mosq->in_packet.to_process -= len;
                        }else{
#ifdef WIN32
                                errno = WSAGetLastError();
#endif
                                if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
                                        return MOSQ_ERR_SUCCESS;
                                }else{
                                        _mosquitto_packet_cleanup(&mosq->in_packet);
                                        switch(errno){
                                                case 0:
                                                        return MOSQ_ERR_PROXY;
                                                case COMPAT_ECONNRESET:
                                                        return MOSQ_ERR_CONN_LOST;
                                                default:
                                                        return MOSQ_ERR_ERRNO;
                                        }
                                }
                        }
                }
		//printf("in_packet.packet_length = %d\r\n", mosq->in_packet.packet_length);
		/*
		for (i = 0; i < mosq->in_packet.packet_length; i++) {
		    printf("%d\r\n", mosq->in_packet.payload[i]);
		}*/
                if(mosq->in_packet.packet_length >= 12){
                        /* First part of the packet has been received, we now know what else to expect */
			if (!memmem(&(mosq->in_packet.payload[0]), mosq->in_packet.packet_length, (uint8_t *)"\r\n\r\n", 4)){
			    //printf("not found\r\n");
			    mosq->in_packet.to_process += 1;
			    mosq->in_packet.packet_length += 1;

			    payload = _mosquitto_realloc(mosq->in_packet.payload, mosq->in_packet.packet_length);
		            if(payload){
		               mosq->in_packet.payload = payload;
    			    }else{
            			_mosquitto_packet_cleanup(&mosq->in_packet);
            			return MOSQ_ERR_NOMEM;
    			    }
			    return MOSQ_ERR_SUCCESS;
			}

			//printf("found\r\n");
			if(!memmem(&(mosq->in_packet.payload[0]), 12, (uint8_t *)"HTTP/1.0 200", 12)){
			    if(!memmem(&(mosq->in_packet.payload[0]), 12, (uint8_t *)"HTTP/1.1 200", 12)){
		  		//printf("proxy bad response\r\n");
				memcpy(&(resp[0]), &(mosq->in_packet.payload[9]), 3);
				resp[3] = 0;
                                _mosquitto_packet_cleanup(&mosq->in_packet);

				// check the proxy response. only 407 is recognized for now.
				if(!strcmp(resp, "407"))
				    return MOSQ_ERR_AUTH;
				else
				    return MOSQ_ERR_PROXY;
			    }
			}
			//printf("connection established\r\n");
			_mosquitto_packet_cleanup(&mosq->in_packet);
			mosq->state = mosq_cs_new;
#ifdef WITH_TLS
			rc = _mosquitto_socket_starttls(mosq);
			if(rc != MOSQ_ERR_SUCCESS) return rc;
#endif
			return _mosquitto_send_connect(mosq, mosq->keepalive, mosq->clean_session);
                }

	}else{
	    return _mosquitto_packet_read(mosq);
	}
	return MOSQ_ERR_SUCCESS;
}
#endif
