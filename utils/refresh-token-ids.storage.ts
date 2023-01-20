import { redisClient } from "../app";

export class InvalidateRefreshTokenError extends Error {}

const insert = async (userId: number, tokenId: string): Promise<void> => {
  await redisClient.set(getKey(userId), tokenId);
};

const validate = async (userId: number, tokenId: string): Promise<boolean> => {
  const storedId = await redisClient.get(getKey(userId));

  if (storedId !== tokenId) {
    throw new InvalidateRefreshTokenError();
  }

  return storedId === tokenId;
};

const invalidate = async (userId: number): Promise<void> => {
  await redisClient.del(getKey(userId));
};

const getKey = (userId: number): string => {
  return `user-${userId}`;
};

export { insert, validate, invalidate };
