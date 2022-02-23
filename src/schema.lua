local typedefs = require "kong.db.schema.typedefs"

return {
    name = "digiprime-jwt",
    fields = {
        {protocols = typedefs.protocols_http},
        {
            config = {
                type = "record",
                fields = {
                    {
                        uri_param_names = {
                            type = "set",
                            elements = {type = "string"},
                            default = {"jwt"}
                        }
                    },
                    {secret_is_base64 = {type = "boolean", required = true, default = false}},
                    {secret_key = {type = "string", required = true, default = "f81ebc2f-f4b2-ff8e-cae9-dacce0270c88"}},
                    {
                        maximum_expiration = {
                            type = "number",
                            default = 0,
                            between = {0, 31536000}
                        }
                    },
                    {
                        header_names = {
                            type = "set",
                            elements = {type = "string"},
                            default = {"authorization"}
                        }
                    },
                    {
                        skip_uri = {
                            type = "array",
                            elements = {type = "string"},
                            default = {"GET=>/ping"}
                        }
                    }
                }
            }
        }
    },
    entity_checks = {
        {
            conditional = {
                if_field = "config.maximum_expiration",
                if_match = {gt = 0},
                then_field = "config.claims_to_verify",
                then_match = {contains = "exp"}
            }
        }
    }
}
