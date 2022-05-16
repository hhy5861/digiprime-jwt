local typedefs = require "kong.db.schema.typedefs"

return {
    name = "digiprime-jwt",
    fields = {
        { protocols = typedefs.protocols_http },
        {
            config = {
                type = "record",
                fields = {
                    {
                        uri_param_names = {
                            type = "set",
                            elements = { type = "string", required = false, default = "token" },
                        }
                    },
                    { secret_is_base64 = { type = "boolean", required = true, default = false } },
                    { secret_key = { type = "string", required = true, default = "^yTrOcL1Mkx!WJHOtVeun#mXjxc*DjBA" } },
                    { is_expiration = { type = "boolean", required = false, default = false } },
                    {
                        header_names = {
                            type = "set",
                            elements = { type = "string" },
                            default = { "Authorization", "x-token" }
                        }
                    },
                    {
                        exclude_method_path = {
                            type = "array",
                            elements = { type = "string" },
                            default = { "GET=>/index" }
                        }
                    }
                }
            }
        }
    },
    entity_checks = {}
}
