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

#ifndef HTTPPROXY_MOSQ_H
#define HTTPPROXY_MOSQ_H

int mosquitto__httpproxy_send(struct mosquitto *mosq);
int mosquitto__httpproxy_read(struct mosquitto *mosq);

#endif
