local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.digiprime-jwt.jwt_parser"
local sequence = require "kong.plugins.digiprime-jwt.asn_sequence"
local router = require "router"

local fmt = string.format
local kong = kong
local type = type
local error = error
local ipairs = ipairs
local tostring = tostring
local re_gmatch = ngx.re.gmatch
local _ = require "lodash"

local JwtHandler = {
  PRIORITY = 1005,
  VERSION = "0.0.1",
}

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the configured header_names (defaults to `[Authorization]`).
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
  local args = kong.request.get_query()
  for _, v in ipairs(conf.uri_param_names) do
    if args[v] then
      return args[v]
    end
  end

  local var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local cookie = var["cookie_" .. v]
    if cookie and cookie ~= "" then
      return cookie
    end
  end

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

local function set_headers(claims)
  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  _.forEach(sequence.HEADERS, function(key)
    local values = claims[key]
    if values then
      set_header(key, user)
    else
      clear_header(key)
    end
  end)

end

local function skip_uri(conf)
  local r = router.new()
  local is_skip = false

  _.forEach(conf.skip_get_uri, function(uri)
    r.match("GET", uri, function()
      is_skip = true
    end)
  end)

  _.forEach(conf.skip_post_uri, function(uri)
    r.match("POST", uri, function()
      is_skip = true
    end)
  end)

  _.forEach(conf.skip_put_uri, function(uri)
    r.match("PUT", uri, function()
      is_skip = true
    end)
  end)

  _.forEach(conf.skip_delete_uri, function(uri)
    r.match("DELETE", uri, function()
      is_skip = true
    end)
  end)

  _.forEach(conf.skip_head_uri, function(uri)
    r.match("HEAD", uri, function()
      is_skip = true
    end)
  end)

  _.forEach(conf.skip_patch_uri, function(uri)
    r.match("PATCH", uri, function()
      is_skip = true
    end)
  end)

  local method = kong.request.get_method()
  local uri = kong.request.get_path()
  r:execute(method, uri)

  return is_skip
end

local function do_authentication(conf)
  local token, err = retrieve_token(conf)
  if err then
    return error(err)
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
  local jwt, err = jwt_decoder:new(token)
  if err then
    return false, { status = 401, message = "Bad token; " .. tostring(err) }
  end

  local claims = jwt.claims
  local header = jwt.header

  local algorithm = header.alg
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

  set_headers(claims)

  return true
end

function JwtHandler:access(conf)
  -- check if preflight request and whether it should be authenticated
  if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
    return kong.response.exit(err.status, err.errors or { message = err.message })
  end
end

return JwtHandler
