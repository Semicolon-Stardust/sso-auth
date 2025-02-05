// src/utils/signaleLogger.js
import pkg from 'signale';
const { Signale } = pkg;

const signale = new Signale({
  scope: 'SSO-Auth'
});

export default signale;
