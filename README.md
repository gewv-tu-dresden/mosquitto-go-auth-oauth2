# Mosquitto Go Auth Plugin for OAuth2

This is a custom backend for the [mosquitto go auth plugin](https://github.com/iegomez/mosquitto-go-auth) that can handle the authentication and authorization with a oauth2 server.

## How to use

This plugin use oauth to authenticate and authorize users for a mqtt broker. Unfortunately is it necessary, that the oauth server response with allowed topics for the user. So the authentication is simple and possible with all kinds of oauth servers. But for the acl check, server have to answer with a special json on the userinfo endpoint. This is the structur: 

```json
{
    "mqtt": {
        "topics": {
            "read": ["sensor/+/rx"],
            "write": ["application/#", "server_log/mqtt_broker/tx"]
        },
        "superuser": false
    }
}

```

We use Keycloak and there you can customize your userinfo.

Configuration options are listed below:

| Options                    | Description                                                                                                                                                        | Mandatory |
|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------:|
| `oauth_client_id`          | Oauth2 Client id.                                                                                                                                                  |     Y     |
| `oauth_client_secret`      | Oauth2 Client secret. Either `oauth_client_secret` or `oauth_client_secret_file` must be set. If both are set, `oauth_client_secret_file` is used.                 |     N     |
| `oauth_client_secret_file` | File containing Oauth2 Client secret. Either `oauth_client_secret` or `oauth_client_secret_file` must be set. If both are set, `oauth_client_secret_file` is used. |     N     |
| `oauth_token_url`          | `token` endpoint url of the Oauth2 server.                                                                                                                         |     Y     |
| `oauth_userinfo_url`       | `userinfo` endpoint url of the Oauth2 server.                                                                                                                      |     Y     |
| `oauth_cache_duration`     | Cache duration (in seconds) before the plugin request user info from Oauth2 server. `0` by default.                                                                |     N     |
| `oauth_scopes`             | Comma separated list of requested scopes. No scope by default.                                                                                                     |     N     |

## How to test

The simplest way is to use the delivered dockerfile and build your own image. You can use volumes to import the configurations or copy the files in the images while you build it.
If you use volumes you have to remove the `COPY` commands from the Dockerfile.