import sodium from 'libsodium-wrappers-sumo';

let isInitialized = false;

export const initSodium = async () => {
  if (!isInitialized) {
    await sodium.ready;
    isInitialized = true;
  }
};

export { sodium }; 