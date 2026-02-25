function safeDbToLinear(db) {
  const v = Number.isFinite(db) ? db : -120;
  return Math.pow(10, Math.max(v, -120) / 20);
}

function mean(values) {
  if (!values.length) return 0;
  return values.reduce((acc, n) => acc + n, 0) / values.length;
}

function stdDev(values, avg) {
  if (!values.length) return 0;
  const variance = values.reduce((acc, n) => acc + (n - avg) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function normalizeVector(vector) {
  let mag = 0;
  for (const v of vector) mag += v * v;
  mag = Math.sqrt(mag);
  if (!mag) return null;
  return vector.map((v) => v / mag);
}

export async function captureVoiceEmbedding(durationMs = 3500) {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("Microphone capture is not supported in this browser");
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    audio: {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    },
  });

  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const audioCtx = new AudioCtx();
  const source = audioCtx.createMediaStreamSource(stream);
  const analyser = audioCtx.createAnalyser();

  analyser.fftSize = 2048;
  analyser.smoothingTimeConstant = 0.8;
  source.connect(analyser);

  const freqData = new Float32Array(analyser.frequencyBinCount);
  const timeData = new Float32Array(analyser.fftSize);

  const rmsSeries = [];
  const zcrSeries = [];
  const centroidSeries = [];
  const rolloffSeries = [];
  const bandCount = 6;
  const bandSeries = Array.from({ length: bandCount }, () => []);

  const sampleRate = audioCtx.sampleRate;
  const nyquist = sampleRate / 2;

  const interval = setInterval(() => {
    analyser.getFloatFrequencyData(freqData);
    analyser.getFloatTimeDomainData(timeData);

    let rms = 0;
    let zcr = 0;
    for (let i = 0; i < timeData.length; i++) {
      const s = timeData[i];
      rms += s * s;
      if (i > 0 && Math.sign(timeData[i - 1]) !== Math.sign(s)) zcr += 1;
    }
    rms = Math.sqrt(rms / timeData.length);
    zcr = zcr / timeData.length;
    rmsSeries.push(rms);
    zcrSeries.push(zcr);

    const magnitudes = new Array(freqData.length);
    let totalMag = 0;
    let weightedFreq = 0;
    for (let i = 0; i < freqData.length; i++) {
      const mag = safeDbToLinear(freqData[i]);
      magnitudes[i] = mag;
      totalMag += mag;
      const hz = (i / freqData.length) * nyquist;
      weightedFreq += hz * mag;
    }

    const centroid = totalMag ? weightedFreq / totalMag : 0;
    centroidSeries.push(centroid / nyquist);

    const target = totalMag * 0.85;
    let cumulative = 0;
    let rolloffHz = 0;
    for (let i = 0; i < magnitudes.length; i++) {
      cumulative += magnitudes[i];
      if (cumulative >= target) {
        rolloffHz = (i / magnitudes.length) * nyquist;
        break;
      }
    }
    rolloffSeries.push(rolloffHz / nyquist);

    const binsPerBand = Math.floor(magnitudes.length / bandCount);
    for (let b = 0; b < bandCount; b++) {
      const start = b * binsPerBand;
      const end = b === bandCount - 1 ? magnitudes.length : start + binsPerBand;
      let bandSum = 0;
      for (let i = start; i < end; i++) bandSum += magnitudes[i];
      bandSeries[b].push(totalMag ? bandSum / totalMag : 0);
    }
  }, 50);

  await new Promise((resolve) => setTimeout(resolve, durationMs));
  clearInterval(interval);

  stream.getTracks().forEach((t) => t.stop());
  source.disconnect();
  analyser.disconnect();
  await audioCtx.close();

  if (rmsSeries.length < 10) {
    throw new Error("Voice sample too short. Please try again.");
  }

  const features = [];
  const baseSeries = [rmsSeries, zcrSeries, centroidSeries, rolloffSeries];
  for (const series of baseSeries) {
    const m = mean(series);
    features.push(m, stdDev(series, m));
  }

  for (const series of bandSeries) {
    const m = mean(series);
    features.push(m, stdDev(series, m));
  }

  const normalized = normalizeVector(features);
  if (!normalized) {
    throw new Error("Failed to extract voice features. Please try again.");
  }

  return normalized;
}
