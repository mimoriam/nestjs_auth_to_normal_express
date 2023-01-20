import { authenticator } from "otplib";
import { AppDataSource } from "../app";
import { User } from "../models/User.entity";

const generateSecret = async (email: string) => {
  const secret = authenticator.generateSecret();
  const appName = process.env.TFA_APP_NAME;

  const uri = authenticator.keyuri(email, appName, secret);

  return { uri, secret };
};

const verifyCode = async (code: string, secret: string) => {
  return authenticator.verify({
    token: code,
    secret,
  });
};

const enableTfaForUser = async (email: string, secret: string) => {
  const userRepo = AppDataSource.getRepository(User);
  const { id } = await userRepo.findOneOrFail({
    where: { email },
    select: { id: true },
  });

  await userRepo.update(
    { id },
    // Ideally we want to encrypt the "secret" instead of storing in plaintext
    // Use encryption here instead of hashing
    { tfaSecret: secret, isTfaEnabled: true }
  );
};

export { generateSecret, verifyCode, enableTfaForUser };
