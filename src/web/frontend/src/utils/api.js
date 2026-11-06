import axios from 'axios';

const API_BASE_URL = '/api';

const api = {
  // Snippet related methods
  async getSnippets(params = {}) {
    const response = await axios.get(`${API_BASE_URL}/snippets`, { params });
    return response.data;
  },

  async getSnippet(uuid) {
    const response = await axios.get(`${API_BASE_URL}/snippets/${uuid}`);
    return response.data;
  },

  async getChildSnippets(uuid) {
    const response = await axios.get(`${API_BASE_URL}/snippets/${uuid}/children`);
    return response.data;
  },

  // Stats related methods
  async getStats(params = {}) {
    const response = await axios.get(`${API_BASE_URL}/stats`, { params });
    return response.data;
  },

  // Model related methods
  async getModels() {
    const response = await axios.get(`${API_BASE_URL}/models`);
    return response.data;
  },

  async getLanguages() {
    const response = await axios.get(`${API_BASE_URL}/languages`);
    return response.data;
  },

  async getExtendedStats() {
    const response = await axios.get(`${API_BASE_URL}/extended-stats`);
    return response.data;
  },

  async getPairs(params = {}) {
    const response = await axios.get(`${API_BASE_URL}/pairs`, { params });
    return response.data;
  },

  async getPairsCount(params = {}) {
    const response = await axios.get(`${API_BASE_URL}/pairs/count`, { params });
    return response.data;
  },

  async getResources() {
    const response = await axios.get(`${API_BASE_URL}/resources`);
    return response.data;
  },
};

export default api;
