require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const Redis = require("ioredis");
const { createAdapter } = require("@socket.io/redis-adapter");

const app = express();
app.use(cors());

const server = http.createServer(app);

// Redis setup
const redisUrl = process.env.REDIS_URL;
const pubClient = redisUrl ? new Redis(redisUrl) : new Redis();
const subClient = pubClient.duplicate();
const redisClient = pubClient.duplicate();

// Lua scripts for atomic matchmaking operations
const ATOMIC_JOIN_MATCHMAKING_SCRIPT = `
  local queueKey = KEYS[1]
  local socketKey = KEYS[2]
  local matchKey = KEYS[3]
  local entry = ARGV[1]
  local userId = ARGV[2]
  local socketId = ARGV[3]
  local matchDetails = ARGV[4]

  local existingQueueKey = redis.call('HGET', socketKey, 'queueKey')
  if existingQueueKey then
    local elements = redis.call('LRANGE', existingQueueKey, 0, -1)
    if elements and #elements > 0 then
      for i = 1, #elements do
        local parsed = cjson.decode(elements[i])
        if parsed and (parsed.socketId == socketId or parsed.userId == userId) then
          redis.call('LREM', existingQueueKey, 0, elements[i])
        end
      end
    end
  end

  local opponentStr = redis.call('LPOP', queueKey)
  if opponentStr then
    local opponent = cjson.decode(opponentStr)
    if opponent.userId == userId then
      redis.call('RPUSH', queueKey, opponentStr)
    else
      local created = redis.call('SET', matchKey, matchDetails, 'NX', 'EX', 3600)
      if created then
        local oppKey = 'socket:' .. opponent.socketId
        redis.call('HSET', socketKey, 'matchId', matchKey)
        redis.call('HSET', oppKey, 'matchId', matchKey)
        redis.call('HDEL', socketKey, 'queueKey')
        redis.call('HDEL', oppKey, 'queueKey')
        return cjson.encode({ status = 'MATCH_FOUND', opponent = opponent })
      else
        redis.call('RPUSH', queueKey, opponentStr)
      end
    end
  end

  local elements = redis.call('LRANGE', queueKey, 0, -1)
  if elements and #elements > 0 then
    for i = 1, #elements do
      local parsed = cjson.decode(elements[i])
      if parsed and (parsed.socketId == socketId or parsed.userId == userId) then
        redis.call('LREM', queueKey, 0, elements[i])
      end
    end
  end
  redis.call('RPUSH', queueKey, entry)
  redis.call('HSET', socketKey, 'queueKey', queueKey)
  return cjson.encode({ status = 'QUEUED' })
`;

const ATOMIC_LEAVE_MATCHMAKING_SCRIPT = `
  local socketKey = KEYS[1]
  local userId = ARGV[1]
  local socketId = ARGV[2]

  local existingQueueKey = redis.call('HGET', socketKey, 'queueKey')
  if existingQueueKey then
    local elements = redis.call('LRANGE', existingQueueKey, 0, -1)
    if elements and #elements > 0 then
      for i = 1, #elements do
        local parsed = cjson.decode(elements[i])
        if parsed and (parsed.socketId == socketId or parsed.userId == userId) then
          redis.call('LREM', existingQueueKey, 0, elements[i])
        end
      end
    end
    redis.call('HDEL', socketKey, 'queueKey')
  end
  return 1
`;

const ATOMIC_DISCONNECT_CLEANUP_SCRIPT = `
  local socketKey = KEYS[1]
  local userId = ARGV[1]
  local socketId = ARGV[2]

  local existingQueueKey = redis.call('HGET', socketKey, 'queueKey')
  if existingQueueKey then
    local elements = redis.call('LRANGE', existingQueueKey, 0, -1)
    if elements and #elements > 0 then
      for i = 1, #elements do
        local parsed = cjson.decode(elements[i])
        if parsed and (parsed.socketId == socketId or parsed.userId == userId) then
          redis.call('LREM', existingQueueKey, 0, elements[i])
        end
      end
    end
  end

  local matchId = redis.call('HGET', socketKey, 'matchId')
  local opponentSocketId = ''

  if matchId then
    local matchStr = redis.call('GET', 'match:' .. matchId)
    if matchStr then
      local match = cjson.decode(matchStr)
      if match and match.status ~= 'completed' then
        match.status = 'completed'
        redis.call('SET', 'match:' .. matchId, cjson.encode(match), 'EX', 3600)
        for i, p in ipairs(match.players) do
          if p.socketId ~= socketId then
            opponentSocketId = p.socketId
          end
          redis.call('HDEL', 'socket:' .. p.socketId, 'matchId')
        end
      end
    end
  end

  redis.call('DEL', socketKey)
  redis.call('DEL', 'ratelimit:' .. socketId)

  return cjson.encode({ opponentSocketId = opponentSocketId })
`;

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      const allowed = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://algobuddy.vercel.app",
        "https://www.algobuddy.me",
        "https://algobuddy.me"
      ];
      if (allowed.includes(origin) || origin.endsWith(".vercel.app")) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"],
  },
  adapter: createAdapter(pubClient, subClient)
});

const PORT = process.env.PORT || 4000;

// JWT Authentication
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET;

function verifyAuthToken(token) {
  if (!token || !SUPABASE_JWT_SECRET) return null;
  try {
    const decoded = jwt.verify(token, SUPABASE_JWT_SECRET, { algorithms: ["HS256"] });
    return decoded;
  } catch (err) {
    return null;
  }
}

// Connection rate limiting to prevent JWT brute-forcing
const connectionAttempts = new Map();
const MAX_CONNECTION_ATTEMPTS = 5;
const CONNECTION_ATTEMPT_WINDOW_MS = 60000;

function isConnectionRateLimited(ip) {
  const now = Date.now();
  const entry = connectionAttempts.get(ip);
  if (!entry || now > entry.resetTime) {
    connectionAttempts.set(ip, { count: 1, resetTime: now + CONNECTION_ATTEMPT_WINDOW_MS });
    return false;
  }
  entry.count++;
  return entry.count > MAX_CONNECTION_ATTEMPTS;
}

// Rate Limiting Config (Redis-backed token bucket)
const MAX_TOKENS = 10;
const REFILL_RATE_MS = 200;

async function isRateLimited(socketId) {
  const key = `ratelimit:${socketId}`;
  const now = Date.now();
  
  const script = `
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local max_tokens = tonumber(ARGV[2])
    local refill_rate = tonumber(ARGV[3])
    
    local data = redis.call('HMGET', key, 'tokens', 'lastRequestTime')
    local tokens = tonumber(data[1])
    local lastRequestTime = tonumber(data[2])
    
    if not tokens then
      redis.call('HMSET', key, 'tokens', max_tokens - 1, 'lastRequestTime', now)
      redis.call('EXPIRE', key, 60)
      return 0
    end
    
    local timePassed = now - lastRequestTime
    local tokensToAdd = math.floor(timePassed / refill_rate)
    
    if tokensToAdd > 0 then
      tokens = math.min(max_tokens, tokens + tokensToAdd)
      lastRequestTime = now
    end
    
    if tokens > 0 then
      redis.call('HMSET', key, 'tokens', tokens - 1, 'lastRequestTime', lastRequestTime)
      redis.call('EXPIRE', key, 60)
      return 0
    end
    return 1
  `;
  
  const result = await redisClient.eval(script, 1, key, now, MAX_TOKENS, REFILL_RATE_MS);
  return result === 1;
}

io.on("connection", (socket) => {
  // Connection-level rate limiting to prevent JWT brute-forcing
  const clientIp = socket.handshake.address;
  if (isConnectionRateLimited(clientIp)) {
    socket.emit("error", { message: "Too many connection attempts. Please try again later." });
    socket.disconnect(true);
    return;
  }

  // Verify Supabase JWT from handshake auth
  const token = socket.handshake.auth?.token;
  const authPayload = verifyAuthToken(token);
  if (!authPayload) {
    socket.emit("error", { message: "Authentication required. Please sign in again." });
    socket.disconnect(true);
    return;
  }

  // Store verified userId from the JWT payload — never trust client-supplied userId
  socket.data.userId = authPayload.sub || authPayload.id;
  console.log(`Authenticated user connected: ${socket.id}, userId: ${socket.data.userId}`);

  socket.on("join_matchmaking", async (data) => {
    if (await isRateLimited(socket.id)) return;

    console.log(`User joined matchmaking: userId=${socket.data.userId}`);
    const targetTopic = data.topic || "Arrays";
    const targetDifficulty = data.difficulty || "Easy";
    const queueKey = `queue:${targetTopic}:${targetDifficulty}`;
    const matchId = `match-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const matchKey = `match:${matchId}`;

    const queueEntry = JSON.stringify({
      ...data,
      userId: socket.data.userId,
      topic: targetTopic,
      difficulty: targetDifficulty,
      socketId: socket.id,
    });

    const matchDetails = JSON.stringify({
      matchId,
      topic: targetTopic,
      difficulty: targetDifficulty,
      status: "in-progress",
      players: [],
    });

    const resultStr = await redisClient.eval(
      ATOMIC_JOIN_MATCHMAKING_SCRIPT,
      3,
      queueKey,
      `socket:${socket.id}`,
      matchKey,
      queueEntry,
      socket.data.userId,
      socket.id,
      matchDetails,
    );

    const result = JSON.parse(resultStr);

    if (result.status === 'MATCH_FOUND') {
      const opponent = result.opponent;
      const fullMatchDetails = {
        matchId,
        topic: targetTopic,
        difficulty: targetDifficulty,
        status: "in-progress",
        players: [
          { userId: opponent.userId, name: opponent.name, socketId: opponent.socketId },
          { userId: socket.data.userId, name: data.name || "Player", socketId: socket.id },
        ],
      };

      await redisClient.set(matchKey, JSON.stringify(fullMatchDetails));

      io.to(opponent.socketId).emit("match_found", fullMatchDetails);
      io.to(socket.id).emit("match_found", fullMatchDetails);

      socket.join(matchId);
      io.in(opponent.socketId).socketsJoin(matchId);

      console.log(`Match found: ${opponent.userId} vs ${socket.data.userId}`);
    } else {
      console.log(`Added to queue ${queueKey}`);
    }
  });

  socket.on("leave_matchmaking", async () => {
    if (await isRateLimited(socket.id)) return;
    await redisClient.eval(
      ATOMIC_LEAVE_MATCHMAKING_SCRIPT,
      1,
      `socket:${socket.id}`,
      socket.data.userId,
      socket.id,
    );
  });

  socket.on("join_match", async (data) => {
    // Verify the socket is a participant in the match before allowing room join
    const matchId = await redisClient.hget(`socket:${socket.id}`, "matchId");
    if (!matchId || matchId !== data.matchId) return;
    socket.join(data.matchId);
  });

  // Duel Room Events
  socket.on("code_update", async (data) => {
    if (await isRateLimited(socket.id)) return;
    socket.to(data.matchId).emit("opponent_code_update", {
      code: data.code,
      userId: socket.data.userId
    });
  });

  socket.on("test_submit", async (data) => {
    if (await isRateLimited(socket.id)) return;
    socket.to(data.matchId).emit("opponent_test_submit", { userId: socket.data.userId });
  });

  socket.on("test_result", async (data) => {
    if (await isRateLimited(socket.id)) return;
    
    const matchId = await redisClient.hget(`socket:${socket.id}`, "matchId");
    if (!matchId || matchId !== data.matchId) return;

    socket.to(data.matchId).emit("opponent_test_result", {
      userId: socket.data.userId,
      passed: data.passed,
      total: data.total,
      status: data.status
    });
  });

  socket.on("match_complete", async (data) => {
    if (await isRateLimited(socket.id)) return;
    
    const matchId = await redisClient.hget(`socket:${socket.id}`, "matchId");
    if (!matchId || matchId !== data.matchId) return;
    
    const matchStr = await redisClient.get(`match:${matchId}`);
    if (matchStr) {
      const match = JSON.parse(matchStr);
      if (match.status !== "completed") {
        match.status = "completed";
        await redisClient.set(`match:${matchId}`, JSON.stringify(match));
        
        io.in(matchId).emit("match_ended", { winnerId: socket.data.userId });
        
        for (const p of match.players) {
          await redisClient.hdel(`socket:${p.socketId}`, "matchId");
        }
        await redisClient.expire(`match:${matchId}`, 60 * 60);
      }
    }
  });

  socket.on("disconnect", async () => {
    const resultStr = await redisClient.eval(
      ATOMIC_DISCONNECT_CLEANUP_SCRIPT,
      1,
      `socket:${socket.id}`,
      socket.data.userId,
      socket.id,
    );

    const result = JSON.parse(resultStr);

    if (result.opponentSocketId) {
      io.to(result.opponentSocketId).emit("opponent_disconnected", { winnerId: socket.data.userId });
    }

    console.log(`User disconnected: ${socket.id}`);
  });
});

app.get("/debug", async (req, res) => {
  res.json({
    status: "Redis migration complete. Queue details are stored in Redis.",
    activeConnections: io.engine.clientsCount
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "Arena Socket Server is running with Redis!" });
});

server.listen(PORT, () => {
  console.log(`Arena Socket Server running on port ${PORT}`);
});
