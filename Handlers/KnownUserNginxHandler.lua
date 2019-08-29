local iHelpers = require("KnownUserImplementationHelpers")
local knownUser = require("KnownUser")
local utils = require("Utils")
local ck = require "resty.cookie"

local aHandler = {}

aHandler.handle = function(customerId, secretKey, integrationConfigJson, request_rec, request_var) 
  assert(customerId ~= nil, "customerId invalid")
  assert(secretKey ~= nil, "secretKey invalid")
  assert(integrationConfigJson ~= nil, "integrationConfigJson invalid")
  assert(request_rec ~= nil, "request_rec invalid")
  -- Implement required helpers
  -- ********************************************************************************   
  iHelpers.request.getHeader = function(name)
    return request_rec.get_headers()[name]
  end
  iHelpers.request.getUnescapedCookieValue = function(name) 
    local cookieValue = request_var["cookie_" .. name]
    
    if (cookieValue ~= nil) then
      cookieValue = utils.urlDecode(cookieValue)
    end

    return cookieValue
  end
  iHelpers.request.getAbsoluteUri = function()
    return request_var.scheme .. "://" .. request_var.http_host .. request_var.uri   
  end
  iHelpers.request.getUserHostAddress = function()
    return request_rec.useragent_ip
  end


  local cookie, err = ck:new()
  iHelpers.response.setCookie = function(name, value, expire, domain)
    if (domain == nil) then
      domain = ""
    end
    
    cookie:set({
      key = name,
      value = value,
      expires = expire,
      secure = false,
      httponly = false,
      path = "/",
      domain = domain
    })
  end
  -- ********************************************************************************
  -- END Implement required helpers

  --Adding no cache headers to prevent browsers to cache requests
  request_rec.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
  request_rec.set_header("Pragma", "no-cache")
  request_rec.set_header("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
  --end

  local args, err = ngx.req.get_uri_args()
  local queueitToken = args["queueittoken"]
  local fullUrl = iHelpers.request.getAbsoluteUri()
  local currentUrlWithoutQueueitToken = fullUrl:gsub("([\\%?%&])(" .. knownUser.QUEUEIT_TOKEN_KEY .. "=[^&]*)", "")
  
  local validationResult = knownUser.validateRequestByIntegrationConfig(currentUrlWithoutQueueitToken, queueitToken, integrationConfigJson, customerId, secretKey)

  if (validationResult:doRedirect()) then
    if (validationResult.isAjaxResult == false) then
      return ngx.redirect(validationResult.redirectUrl)
    else
      ngx.header[validationResult.getAjaxQueueRedirectHeaderKey()] = validationResult:getAjaxRedirectUrl()
      return ngx.OK
    end
  else
    -- Request can continue - we remove queueittoken form querystring parameter to avoid sharing of user specific token if did not match
    if (fullUrl ~= currentUrlWithoutQueueitToken and validationResult.actionType ~= nil) then
      return ngx.redirect(currentUrlWithoutQueueitToken)
    end
  end
end

return aHandler