import axios from 'axios';

const BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const api = axios.create({ baseURL: BASE, timeout: 30000 });

export const predictURL = (url, networkFeatures = null) =>
  api.post('/predict', { url, network_features: networkFeatures }).then(r => r.data);

export const predictMLOnly = (url) =>
  api.post('/predict/ml-only', { url }).then(r => r.data);

export const predictWFAOnly = (url) =>
  api.post('/predict/wfa-only', { url }).then(r => r.data);

export const uploadNetworkCSV = (file) => {
  const form = new FormData();
  form.append('file', file);
  return api.post('/upload/network-csv', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(r => r.data);
};

export const getWFADiagram = () =>
  api.get('/wfa/diagram').then(r => r.data);

export const getModelStatus = () =>
  api.get('/model/status').then(r => r.data);

export const getHealth = () =>
  api.get('/health').then(r => r.data);
