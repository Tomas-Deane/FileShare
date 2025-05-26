module.exports = function override(config) {
  config.resolve.fallback = {
    "crypto": false
  };
  return config;
}; 