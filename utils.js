import CryptoJS from 'crypto-js';
import redis from  'redis';

const SECRET_KEY = 'JKL_131';
const TIME_WINDOW = 5 * 60 * 1000; // 5 minutes in milliseconds
const REDIS_HOST = 'localhost';
const REDIS_PORT = 6379;

const client = redis.createClient({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: 'kjas@dflk3', // 用你的密碼替換
  /*tls: {
    // TLS 配置
  }*/
});
client.on('error', (err) => {
  console.error('Redis error:', err);
});

const generateSign = (params, secretKey) => {
  const sortedParams = Object.keys(params).sort().map(key => `${key}=${params[key]}`).join('&');
  return CryptoJS.HmacSHA256(sortedParams, secretKey).toString(CryptoJS.enc.Hex);
};

const verifySign = (params, providedSign, secretKey) => {
  const generatedSign = generateSign(params, secretKey);
  return generatedSign === providedSign;
};

const verifyRequest = async (params, providedSign) => {
  // Verify signature
  if (!verifySign(params, providedSign, SECRET_KEY)) {
    return false; // Signature mismatch
  }

  // Verify timestamp
  const timestamp = parseInt(params.timestamp, 10);
  const currentTime = Date.now();
  if (Math.abs(currentTime - timestamp) > TIME_WINDOW) {
    return false; // Timestamp out of valid window
  }

  // Verify nonce
  const nonce = params.nonce;
  return new Promise((resolve, reject) => {
    client.exists(params.nonce, (err, reply) => {
      if (err) return reject(err);
      if (reply === 1) {
        return resolve(false); // Nonce already exists
      }
      client.setEx(params.nonce, TIME_WINDOW / 1000, '1', (err) => {
        if (err) return reject(err);
        resolve(true);
      });
    });
  });
  return true;
};

export const verifyRequestSignature = (req, res, next) => {
  const signature = req.headers['x-signature'];
  const params={...req.body,file:req.file}
  const data = JSON.stringify(params);
  try{
  if(verifyRequest(data, signature)){
    next()
  }else{
    res.status(401).send('Unauthorized');
    }
  }catch(err){
    res.status(500).send('Internal Server Error');
  }
}