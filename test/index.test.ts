import { Strategy } from '../src'
import express from 'express';
import nock from 'nock';

beforeEach(() => {
  nock('https://127.0.0.1')
    .get('/.well-known/openid-configuration')
    .reply(200, {
      authorization_endpoint: 'https://127.0.0.1/authorize'
    })
})

describe('Strategy', () => {
  const strategy = new Strategy({
    client_id: 'TEST_CLIENT_ID',
    client_secret: 'TEST_CLIENT_SECRET',
    redirect_uri: 'TEST_REDIRECT_URI',
    url: 'https://127.0.0.1/.well-known/openid-configuration'
  });
  const mockRequest = {
    query: {
    },
    session: {
    }
  } as unknown as express.Request;
  it('authenticate should not throw error', () => {
    strategy.authenticate(mockRequest, {});
  })
})