import { parentPort, workerData } from 'worker_threads';
import autocrop from 'autocrop-js';
import { removeBackground } from '@imgly/background-removal-node';
import fs from 'fs/promises';

const dataUrlToBuffer = (dataUrl) => {
  const base64String = dataUrl.split(',')[1];
  return Buffer.from(base64String, 'base64');
};

(async () => {
  try {
    const { imgPath, originalName } = workerData;
    const processedBuffer = await removeBackground(imgPath);
    const buffer = Buffer.from(await processedBuffer.arrayBuffer());
    const result = await autocrop(buffer, { alphaThreshold: 10 });
    const croppedBuffer = dataUrlToBuffer(result.dataURL);

    // 将结果转换为Base64发送回主线程
    parentPort.postMessage(croppedBuffer.toString('base64'));
  } catch (error) {
    parentPort.postMessage({ error: error.message });
  }
})();