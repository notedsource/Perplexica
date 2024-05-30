import { auth } from 'google-auth-library';
import { getAccessKey, useJWT } from './config';
import jwt from 'jsonwebtoken';

export const requireAccessKey = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    if (!checkAccessKey(authHeader)) {
      return res.sendStatus(403);
    }
    next();
  } else {
    res.sendStatus(401);
  }
};

export const verifyJWT = (token, accessKey) => {
  try {
    const verified = jwt.verify(token, accessKey);
    const expAccessToken = verified.exp; // in seconds
    const now = Math.floor(Date.now() / 1000); // in seconds
    const remaining = expAccessToken - now; // in seconds
    return Boolean(remaining > 0);
  } catch (e) {
    return false;
  }
};

export const checkAccessKey = (authHeader) => {
  const token = authHeader.split(' ')[1];
  const accessKey = getAccessKey();

  if (useJWT) {
    return verifyJWT(token, accessKey);
  }

  return Boolean(authHeader && token === accessKey);
};

export const hasGCPCredentials = async () => {
  try {
    const credentials = await auth.getCredentials();
    return Object.keys(credentials).length > 0;
  } catch (e) {
    return false;
  }
};
