import React from 'react';
import { BskyAgent } from '@atproto/api';


export interface SessionAccount {
  service: string;
  did: string;
  handle: string;
  accessJwt: string;
  refreshJwt: string;
  active?: boolean;
  status?: 'takendown' | 'deactivated' | 'active';
  signupQueued?: boolean;
  email?: string;
  emailConfirmed?: boolean;
  emailAuthFactor?: boolean;
  pdsUrl?: string;
  isSelfHosted?: boolean;
}

interface SessionStateContext {
  currentAccount: SessionAccount | undefined;
  accounts: SessionAccount[];
  hasSession: boolean;
  agent: BskyAgent;
  login: (
    credentials: {
      service: string
      identifier: string
      password: string
      authFactorToken?: string
    },
    event?: {
      name: string
      properties: Record<string, unknown>
    }
  ) => Promise<void>;
  loginWithWallet: (address: string) => Promise<void>;
  loginWithEmail: (email: string) => Promise<void>;
  logout: () => void;
  logoutCurrentAccount: (reason?: string) => void;
  logoutEveryAccount: (reason?: string) => void;
  removeAccount: (did: string) => void;
  resumeSession: (account: Omit<SessionAccount, 'accessJwt'|'refreshJwt'> & {
    accessJwt: string
    refreshJwt: string
  }) => Promise<void>;
  updateSession: (update: Partial<SessionAccount>) => void;
  createAccount: (props: {
    service: string;
    did: string;
    handle: string;
    email?: string;
    accessJwt: string;
    refreshJwt: string;
  }) => void;
  useAgent: () => BskyAgent;
}

export const SessionContext = React.createContext<SessionStateContext>({
  currentAccount: undefined,
  accounts: [],
  hasSession: false,
  agent: new BskyAgent({ service: 'https://bsky.social' }),
  login: async () => {},
  loginWithEmail: async () => {},
  loginWithWallet: async () => {},
  logout: () => {},
  logoutCurrentAccount: () => {},
  logoutEveryAccount: () => {},
  removeAccount: () => {},
  resumeSession: async () => {},
  updateSession: () => {},
  createAccount: () => {},
  useAgent: function() { return this.agent }
});

export const useSession = () => React.useContext(SessionContext);
export const useAgent = () => {
  const {agent} = React.useContext(SessionContext);
  return agent;
};
export const useSessionApi = () => {
  const { 
    login,
    updateSession,
    resumeSession,
    logoutCurrentAccount,
    logoutEveryAccount,
    removeAccount,
    createAccount
  } = React.useContext(SessionContext);
  
  return {
    login,
    updateSession,
    resumeSession,
    logoutCurrentAccount,
    logoutEveryAccount,
    removeAccount,
    createAccount
  };
}

export const useRequireAuth = () => {
  const session = useSession();
  return (fn: Function) => (...args: any[]) => {
    if (!session.currentAccount) {
      throw new Error('Authentication required');
    }
    return fn(...args);
  };
};

// ... rest of session management implementation
