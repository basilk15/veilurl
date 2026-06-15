import mongoose from "mongoose";
import { loadLocalEnv } from "./loadLocalEnv.js";

loadLocalEnv();

let cached = globalThis.__sentinelMongo;

if (!cached) {
  cached = globalThis.__sentinelMongo = {
    conn: null,
    promise: null,
  };
}

export function hasMongoUri() {
  return Boolean(process.env.MONGODB_URI);
}

export async function connectToDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is not configured");
  }

  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    cached.promise = mongoose.connect(process.env.MONGODB_URI, {
      bufferCommands: false,
    });
  }

  cached.conn = await cached.promise;
  return cached.conn;
}
