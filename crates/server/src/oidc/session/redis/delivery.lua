-- All times stay decimal strings. Never cjson-decode stored state or round u64/i64 through Lua doubles.
local function decimal(value)
  return value and string.match(value, "^%d+$") and (value == "0" or string.sub(value, 1, 1) ~= "0")
end
local function before(left, right)
  if string.len(left) ~= string.len(right) then return string.len(left) < string.len(right) end
  return left < right
end
local now = ARGV[2]
local fractional = "0"
if now == "" then
  local time = redis.call("TIME")
  now = time[1]
  if time[2] ~= "0" then fractional = "1" end
end
if not decimal(now) then return redis.error_reply("invalid delivery clock") end
if redis.call("EXISTS", KEYS[1]) == 0 then
  if ARGV[1] == "read" then return {"missing"} else return {-1, 0} end
end
local values = redis.call("HMGET", KEYS[1], "user_id", "logout_jti", "logged_out_at_epoch_secs", "logout_delivery_version", "logout_delivery_deadline")
if not values[1] or values[1] == "" or not values[2] or values[2] == "" or not decimal(values[3])
  or before(now, values[3]) or redis.call("PTTL", KEYS[1]) <= 0 or redis.call("PTTL", KEYS[2]) <= 0
  or redis.call("SISMEMBER", KEYS[2], ARGV[3]) ~= 1 then
  return redis.error_reply("invalid delivery parent")
end
if values[4] and (values[4] ~= "1" or not decimal(values[5])) then
  return redis.error_reply("invalid delivery protocol marker")
end
local prior = redis.call("HGET", KEYS[1], ARGV[4])
if ARGV[1] == "read" then
  return {now, values[1], values[2], values[3], values[4], values[5], prior, fractional}
end
if ARGV[1] ~= "cas" then return redis.error_reply("invalid delivery operation") end
for index = 1, 5 do
  if values[index] ~= ARGV[index + 4] then return {0, 0} end
end
if values[4] ~= "1" or not decimal(values[5]) or not decimal(ARGV[12]) or not decimal(ARGV[13])
  or before(now, ARGV[12]) or not before(now, values[5]) or not before(now, ARGV[13])
  or before(values[5], ARGV[13]) then return {-1, 0} end
if (ARGV[10] == "0" and prior) or (ARGV[10] == "1" and prior ~= ARGV[11]) then return {0, 0} end
if ARGV[14] == "1" then redis.call("HSET", KEYS[1], ARGV[4], ARGV[15]) end
-- HSET retains the existing expiry. No EXPIRE, renewal, parent reconstruction or index allocation.
return {1, redis.call("PTTL", KEYS[1])}
