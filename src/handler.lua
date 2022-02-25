local jwt_decoder = require "kong.plugins.digiprime-jwt.jwt_parser"
local sequence = require "kong.plugins.digiprime-jwt.asn_sequence"
local router = require "router"
local _ = require "lodash"
local radix = require("resty.radixtree")

local kong = kong
local type = type
local error = error
local ipairs = ipairs
local tostring = tostring
local re_gmatch = ngx.re.gmatch
local ngx_log = ngx.log
local ngx_NOTICE = ngx.NOTICE

local DigiprimeJwtHandler = {
    PRIORITY = 1005,
    VERSION = "0.0.1"
}

local function retrieve_token(conf)
    if conf.uri_param_names then
        local args = kong.request.get_query()

        for _, v in ipairs(conf.uri_param_names) do
            if args[v] then
                return args[v]
            end
        end
    end

    if table.getn(conf.header_names) > 0 then
        local request_headers = kong.request.get_headers()
        for _, v in ipairs(conf.header_names) do
            local token_header = request_headers[v]
            if token_header then
                if type(token_header) == "table" then
                    token_header = token_header[1]
                end
                local iterator, iter_err = re_gmatch(token_header, "\\s*[Bb]earer\\s+(.+)")
                if not iterator then
                    kong.log.err(iter_err)
                    break
                end

                local m, err = iterator()
                if err then
                    kong.log.err(err)
                    break
                end

                if m and #m > 0 then
                    return m[1]
                end
            end
        end
    end
end

local function set_headers(claims)
    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    _.forEach(
    sequence.HEADERS,
        function(key)
            local values = claims[key]
            if values then
                set_header(key, values)
            else
                clear_header(key)
            end
        end
    )
end

local function split(s, delimiter)
    local result = {}
    for match in (s .. delimiter):gmatch("(.-)" .. delimiter) do
        table.insert(result, match)
    end
    return result
end

local function exclude_uri(paths)
    local ok = false
    if table.getn(conf.paths) <= 0 then
        return ok
    end

    local r = router.new()

    _.forEach(
    conf.paths,
        function(uri)
            local item = split(uri, "=>")

            local skipMethod = string.upper(item[1])
            local skipUri = item[2]

            if skipMethod == "GET" then
                r:match(
                {
                        GET = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "POST" then
                r:match(
                {
                        POST = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "PUT" then
                r:match(
                {
                        PUT = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "PATCH" then
                r:match(
                {
                        PATCH = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "DELETE" then
                r:match(
                {
                        DELETE = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "TRACE" then
                r:match(
                {
                        TRACE = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "CONNECT" then
                r:match(
                {
                        CONNECT = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "OPTIONS" then
                r:match(
                {
                        PUT = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            elseif skipMethod == "HEAD" then
                r:match(
                {
                        HEAD = {
                            [skipUri] = function(params)
                                ok = true
                            end
                        }
                }
                )
            end
        end
    )

    local requestMethod = kong.request.get_method()
    local requestPath = kong.request.get_path()

    r:execute(string.upper(requestMethod), requestPath)
    return ok
end

local function exclude_uri_v2(paths)
    if table.getn(paths) then
        local radix = require("resty.radixtree")

        local routes = {}
        _.forEach(paths, function(path)
            local item = split(uri, "=>")

            if table.getn(item) > 0 then
                local method = item[1]
                local path = item[2]

                table.insert(routes, {
                    paths = { path },
                    methods = { method },
                    metadata = true,
                })
            end
        end)

        local rx = radix.new(routes)

        local opts = {
            method = kong.request.get_method(),
            vars = kong.request.get_query_arg(),
        }

        local metadata, err = rx:match(kong.request.get_path(), opts)
        if err or metadata == nil then
            return false
        end

        return metadata
    end

    return false
end

local function exclude_domain(conf)
    local isExclude = false
    if table.getn(conf.exclude_domain_name) <= 0 then
        return isExclude
    end

    local requestDomain = kong.request.get_host()

    _.forEach(conf.exclude_domain_name, function(domain)
        if domain == requestDomain then
            isExclude = true
        end
    end)

    return isExclude
end

local function decodeToken(token)
    local jwt, err = jwt_decoder:new(token)
    if err then
        return "", err
    end

    return jwt, nil
end

local function do_authentication(conf)
    local token, err = retrieve_token(conf)
    if err then
        return error(err)
    end

    -- if exclude uri path and domain name
    local domainName = exclude_domain(conf)
    local excludePath = exclude_uri_v2(conf.exclude_method_path)
    kong.log.err("domainName ", domainName)
    kong.log.err("excludePath ", excludePath)

    if excludePath or domainName then
        if type(token) == "string" then
            local jwt, err = decodeToken(token)
            if err == nil then
                set_headers(jwt.claims)
            end
        end

        return true
    end

    local token_type = type(token)
    if token_type ~= "string" then
        if token_type == "nil" then
            return false, { status = 401, message = "Unauthorized" }
        elseif token_type == "table" then
            return false, { status = 401, message = "Multiple tokens provided" }
        else
            return false, { status = 401, message = "Unrecognizable token" }
        end
    end

    -- Decode token to find out who the consumer is
    local jwt, err = decodeToken(token)
    if err ~= nil then
        return false, { status = 401, message = "Bad token; " .. tostring(err) }
    end

    local algorithm = jwt.header.alg
    local jwt_secret_value = algorithm ~= nil and algorithm:sub(1, 2) == "HS" and conf.secret_key

    if conf.secret_is_base64 then
        jwt_secret_value = jwt:base64_decode(jwt_secret_value)
    end

    if not jwt_secret_value then
        return false, { status = 401, message = "Invalid key/secret" }
    end

    -- Now verify the JWT signature
    if not jwt:verify_signature(jwt_secret_value) then
        return false, { status = 401, message = "Invalid signature" }
    end

    -- Verify the JWT registered claims
    if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
        local ok, errors = jwt:check_maximum_expiration(conf.maximum_expiration)
        if not ok then
            return false, { status = 401, errors = errors }
        end
    end

    set_headers(jwt.claims)

    return true
end

function DigiprimeJwtHandler:access(conf)
    -- check if preflight request and whether it should be authenticated
    if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
        return
    end

    local ok, err = do_authentication(conf)
    if not ok then
        return kong.response.exit(err.status, err.errors or { message = err.message })
    end
end

return DigiprimeJwtHandler
