const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer);
const ROOMS = ["Delhi", "Mumbai", "Haryana"];
app.use(express.json({ limit: "10kb" }));

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "client.html")));
app.get(["/delhi", "/mumbai", "/haryana"], (req, res) => res.sendFile(path.join(__dirname, "client.html")));
app.get("/rooms/:room", (req, res) => {
  const room = ROOMS.find((name) => name.toLowerCase() === req.params.room.toLowerCase());
  if (!room) return res.status(404).send("Public server not found.");
  res.sendFile(path.join(__dirname, "client.html"));
});
app.get("/styles.css", (req, res) => res.sendFile(path.join(__dirname, "styles.css")));

const HISTORY_LIMIT = 100;
const PRIVATE_DATA_PATH = path.join(__dirname, "private-rooms.json");
const roomPeople = new Map(ROOMS.map((room) => [room, new Map()]));
const roomHistory = new Map(ROOMS.map((room) => [room, []]));
const privateRooms = new Map();

function privateRoomId(name) {
  return `private:${crypto.createHash("sha256").update(name.trim().replace(/\s+/g, " ").toLocaleLowerCase()).digest("hex")}`;
}

function ownerTokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function savePrivateRooms() {
  const rooms = Array.from(privateRooms, ([id, room]) => ({
    id,
    name: room.name,
    salt: room.salt.toString("hex"),
    passwordHash: room.passwordHash.toString("hex"),
    ownerHash: room.ownerHash,
    createdAt: room.createdAt,
    history: room.history.slice(-HISTORY_LIMIT),
  }));
  const temporaryPath = `${PRIVATE_DATA_PATH}.tmp`;
  fs.writeFileSync(temporaryPath, JSON.stringify({ rooms }, null, 2), "utf8");
  fs.renameSync(temporaryPath, PRIVATE_DATA_PATH);
}

function loadPrivateRooms() {
  try {
    const data = JSON.parse(fs.readFileSync(PRIVATE_DATA_PATH, "utf8"));
    for (const stored of data.rooms || []) {
      if (!stored?.id || !stored.name || !stored.salt || !stored.passwordHash) continue;
      privateRooms.set(stored.id, {
        name: stored.name,
        salt: Buffer.from(stored.salt, "hex"),
        passwordHash: Buffer.from(stored.passwordHash, "hex"),
        ownerHash: stored.ownerHash || "",
        createdAt: stored.createdAt || Date.now(),
        history: Array.isArray(stored.history) ? stored.history.filter((m) => m && typeof m.text === "string").slice(-HISTORY_LIMIT) : [],
        people: new Map(),
      });
    }
  } catch (error) {
    if (error.code !== "ENOENT") console.error("Could not load private room data:", error.message);
  }
}

loadPrivateRooms();

function validRoom(room) {
  return ROOMS.includes(room) ? room : ROOMS[0];
}

function peopleFor(room) {
  return roomPeople.get(room) || privateRooms.get(room)?.people;
}

function historyFor(room) {
  return roomHistory.get(room) || privateRooms.get(room)?.history;
}

function listPeople(room) {
  const people = peopleFor(room);
  return people ? Array.from(people, ([id, person]) => ({ id, name: person.name })) : [];
}

function sendPresence(room) {
  io.to(room).emit("presence", { room, people: listPeople(room) });
}

function removeFromRoom(socket, room) {
  const id = socket.data.browserId;
  const people = peopleFor(room);
  if (!people) return;
  const person = people.get(id);
  if (!person) return;
  person.sockets.delete(socket.id);
  if (person.sockets.size === 0) people.delete(id);
  socket.leave(room);
  sendPresence(room);
}

function enterPrivateRoom(socket, request = {}) {
  const mode = request.mode;
  const roomName = typeof request.name === "string" ? request.name.trim().replace(/\s+/g, " ") : "";
  const password = typeof request.password === "string" ? request.password : "";
  const id = typeof request.id === "string" && /^[\w-]{1,80}$/.test(request.id) ? request.id : "";
  const userName = typeof request.userName === "string" ? request.userName.trim().slice(0, 32) : "";
  const ownerToken = typeof request.ownerToken === "string" && request.ownerToken.length >= 32 ? request.ownerToken : "";
  if (!id || !userName) return { ok: false, error: "Set a username before joining a private server." };
  if (roomName.length < 2 || roomName.length > 40) return { ok: false, error: "Server name must be 2–40 characters." };
  if (password.length < 4 || password.length > 100) return { ok: false, error: "Password must be 4–100 characters." };
  if (!["create", "join"].includes(mode)) return { ok: false, error: "Choose create or join." };

  const roomId = privateRoomId(roomName);
  let room = privateRooms.get(roomId);
  if (mode === "create") {
    if (room) {
      const candidate = crypto.scryptSync(password, room.salt, 64);
      if (!crypto.timingSafeEqual(candidate, room.passwordHash)) {
        return { ok: false, error: "That server name is already taken. Use its password to join, or choose another name." };
      }
    } else {
      if (!ownerToken) return { ok: false, error: "A creator token is required to create a new private server. Reload the page and try again." };
      const salt = crypto.randomBytes(16);
      room = {
        name: roomName,
        salt,
        passwordHash: crypto.scryptSync(password, salt, 64),
        ownerHash: ownerTokenHash(ownerToken),
        createdAt: Date.now(),
        people: new Map(),
        history: [],
      };
      privateRooms.set(roomId, room);
      savePrivateRooms();
    }
  } else {
    if (!room) return { ok: false, error: "Private server not found. Check the name or create it." };
    const candidate = crypto.scryptSync(password, room.salt, 64);
    if (!crypto.timingSafeEqual(candidate, room.passwordHash)) return { ok: false, error: "Incorrect password." };
  }

  const oldRoom = socket.data.room;
  if (oldRoom) removeFromRoom(socket, oldRoom);
  const previous = room.people.get(id);
  const person = previous || { name: userName, sockets: new Set() };
  person.name = userName;
  person.sockets.add(socket.id);
  room.people.set(id, person);
  socket.data.browserId = id;
  socket.data.name = userName;
  socket.data.room = roomId;
  socket.join(roomId);

  const tokenHash = ownerToken ? ownerTokenHash(ownerToken) : "";
  const isOwner = Boolean(room.ownerHash && tokenHash && crypto.timingSafeEqual(Buffer.from(tokenHash, "hex"), Buffer.from(room.ownerHash, "hex")));
  const state = { ok: true, room: roomId, roomName: room.name, messages: room.history, people: listPeople(roomId), isOwner };
  socket.to(roomId).emit("presence", { room: roomId, people: state.people });
  if (!previous) socket.to(roomId).emit("join", `${userName} joined the private server`);
  return state;
}

app.post("/api/private-servers/:mode", (req, res) => {
  const socket = io.sockets.sockets.get(req.body.socketId);
  if (!socket) return res.status(409).json({ ok: false, error: "Chat connection not ready. Try again." });
  const result = enterPrivateRoom(socket, { ...req.body, mode: req.params.mode });
  if (!result.ok) return res.status(400).json(result);
  return res.json(result);
});

app.delete("/api/private-servers/:roomId", (req, res) => {
  const roomId = req.params.roomId;
  const room = privateRooms.get(roomId);
  const token = typeof req.body.ownerToken === "string" ? req.body.ownerToken : "";
  if (!room) return res.status(404).json({ ok: false, error: "Private server not found." });
  if (!/^[a-f0-9]{64}$/i.test(room.ownerHash || "") || !token || ownerTokenHash(token) !== room.ownerHash) {
    return res.status(403).json({ ok: false, error: "Only the server creator can delete this room." });
  }

  io.to(roomId).emit("private-room-deleted", { room: roomId, roomName: room.name });
  for (const socket of io.sockets.sockets.values()) {
    if (socket.data.room === roomId) {
      socket.data.room = null;
      socket.leave(roomId);
    }
  }
  privateRooms.delete(roomId);
  savePrivateRooms();
  return res.json({ ok: true });
});

io.on("connection", (socket) => {
  socket.emit("server-ready", { rooms: ROOMS });

  socket.on("join-public", (request = {}, reply = () => {}) => {
    const room = request.room;
    const id = typeof request.id === "string" && /^[\w-]{1,80}$/.test(request.id) ? request.id : "";
    const name = typeof request.name === "string" ? request.name.trim().slice(0, 32) : "";
    if (!ROOMS.includes(room)) return reply({ ok: false, error: "Choose a valid public server." });
    if (!id || !name) return reply({ ok: false, error: "Set your username before joining." });

    const oldRoom = socket.data.room;
    if (oldRoom && oldRoom !== room) removeFromRoom(socket, oldRoom);
    const people = roomPeople.get(room);
    const isNewPerson = !people.has(id);
    const person = people.get(id) || { name, sockets: new Set() };
    person.name = name;
    person.sockets.add(socket.id);
    people.set(id, person);
    socket.data.browserId = id;
    socket.data.name = name;
    socket.data.room = room;
    socket.join(room);

    const response = { ok: true, room, messages: roomHistory.get(room), people: listPeople(room) };
    sendPresence(room);
    if (isNewPerson) socket.to(room).emit("join", `${name} joined the chat`);
    reply(response);
  });

  socket.on("identify", ({ id, name, room } = {}) => {
    if (typeof id !== "string" || !/^[\w-]{1,80}$/.test(id)) return;
    const safeName = typeof name === "string" ? name.trim().slice(0, 32) : "";
    const selectedRoom = validRoom(room);
    const oldRoom = socket.data.room;
    if (oldRoom && oldRoom !== selectedRoom) removeFromRoom(socket, oldRoom);
    const people = peopleFor(selectedRoom);
    const isNewPerson = !people.has(id);
    const person = people.get(id) || { name: safeName || "Guest", sockets: new Set() };
    if (safeName) person.name = safeName;
    person.sockets.add(socket.id);
    people.set(id, person);
    socket.data.browserId = id;
    socket.data.name = person.name;
    socket.data.room = selectedRoom;
    socket.join(selectedRoom);
    socket.emit("history", { room: selectedRoom, messages: roomHistory.get(selectedRoom) });
    sendPresence(selectedRoom);
    if (isNewPerson) socket.to(selectedRoom).emit("join", `${person.name} joined the chat`);
  });

  socket.on("switch-room", (room) => {
    if (!socket.data.browserId || !ROOMS.includes(room) || socket.data.room === room) return;
    const oldRoom = socket.data.room;
    if (oldRoom) removeFromRoom(socket, oldRoom);
    const people = peopleFor(room);
    const id = socket.data.browserId;
    const previous = people.get(id);
    const person = previous || { name: socket.data.name || "Guest", sockets: new Set() };
    person.sockets.add(socket.id);
    people.set(id, person);
    socket.data.room = room;
    socket.join(room);
    socket.emit("history", { room, messages: roomHistory.get(room) });
    sendPresence(room);
    if (!previous) socket.to(room).emit("join", `${person.name} joined the chat`);
  });

  socket.on("leave-room", () => {
    const room = socket.data.room;
    if (!room) return;
    removeFromRoom(socket, room);
    socket.data.room = null;
  });

  socket.on("private-room", (request = {}, reply = () => {}) => {
    reply(enterPrivateRoom(socket, request));
  });

  socket.on("set-name", (value) => {
    const id = socket.data.browserId;
    const room = socket.data.room;
    const name = typeof value === "string" ? value.trim().slice(0, 32) : "";
    if (!id || !name) return;
    socket.data.name = name;
    if (!room) return;
    const person = peopleFor(room)?.get(id);
    if (!person) return;
    person.name = name;
    sendPresence(room);
  });

  socket.on("msg", (value) => {
    const id = socket.data.browserId;
    const room = socket.data.room;
    const person = id && room && peopleFor(room)?.get(id);
    const text = typeof value === "string" ? value.trim().slice(0, 1000) : "";
    if (!person || !text) return;
    const message = { id: `${Date.now()}-${socket.id}`, senderId: id, sender: person.name, text, timestamp: Date.now() };
    const history = historyFor(room);
    history.push(message);
    if (history.length > HISTORY_LIMIT) history.shift();
    if (privateRooms.has(room)) savePrivateRooms();
    io.to(room).emit("chat", message);
  });

  socket.on("disconnect", () => {
    const id = socket.data.browserId;
    const room = socket.data.room;
    if (room) removeFromRoom(socket, room);
  });
});

httpServer.listen(8080, () => {
  console.log("Server started on port 8080");
  console.log("Open the chat: http://localhost:8080");
});

