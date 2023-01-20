import * as bcrypt from "bcrypt";
import { genSalt } from "bcrypt";

const hash = async (data: string | Buffer): Promise<string> => {
  const salt = await genSalt(10);

  return bcrypt.hash(data, salt);
};

const compare = async (
  data: string | Buffer,
  encrypted: string
): Promise<boolean> => {
  return bcrypt.compare(data, encrypted);
};

export { hash, compare };
