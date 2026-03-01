// Records audio, resamples to 16kHz mono, and returns a Float32Array
// suitable for the WavLM speaker verification model on the backend.
export async function captureVoiceEmbedding(durationMs = 5000) {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("Microphone capture is not supported in this browser");
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    audio: {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: false,
    },
  });

  // Collect raw audio chunks via MediaRecorder
  const chunks = [];
  const recorder = new MediaRecorder(stream);
  recorder.ondataavailable = (e) => {
    if (e.data.size > 0) chunks.push(e.data);
  };

  await new Promise((resolve) => {
    recorder.onstop = resolve;
    recorder.start();
    setTimeout(() => recorder.stop(), durationMs);
  });

  stream.getTracks().forEach((t) => t.stop());

  if (!chunks.length) {
    throw new Error("No audio was recorded. Please try again.");
  }

  // Decode the recorded audio
  const blob = new Blob(chunks, { type: "audio/webm" });
  const arrayBuffer = await blob.arrayBuffer();

  const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);
  await audioCtx.close();

  // Resample to 16kHz mono — what WavLM expects
  const targetSampleRate = 16000;
  const targetLength = Math.ceil(audioBuffer.duration * targetSampleRate);
  const offlineCtx = new OfflineAudioContext(1, targetLength, targetSampleRate);

  const source = offlineCtx.createBufferSource();
  source.buffer = audioBuffer;
  source.connect(offlineCtx.destination);
  source.start(0);

  const resampled = await offlineCtx.startRendering();
  return Array.from(resampled.getChannelData(0));
}
