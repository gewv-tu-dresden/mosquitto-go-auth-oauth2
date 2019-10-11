# Mosquitto Go Auth Plugin for OAuth2

This is a custom backend for the [mosquitto go auth plugin](https://github.com/iegomez/mosquitto-go-auth) that can handle the authentification and authorization with a oauth2 server.

## How to use

This plugin use oauth to authenticate and authorize users for a mqtt broker. Unfornatly is it necassary, that the oauth server response with allowed topics for the user. So the authentication is simple and possible with all kinds of oauth servers. But for the acl check, server have to answer with a special json on the userinfo endpoint. This is the structur: 

```json
{
    "mqtt": {
        "topics": {
            "read": ["sensor/+/rx"],
            "write": ["application/#", "server_log/mqtt_broker/tx"],
        },
        "superuser": false,
    },
}

```

We use Keycloak and there you can customize your userinfo.

## How to test

The simplest way is to use the delivered dockerfile and build your own image. You can use volumes to import the configurations or copy the files in the images while you build it.
If you use volumes you have to remove the `COPY` commands from the Dockerfile.