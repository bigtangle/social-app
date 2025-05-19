import {useState} from 'react';
import type React from 'react';

import {Button, Error} from '../../components';
import {useSession} from '../../state/session';

export const WalletLogin: React.FC = () => {
  const {loginWithWallet} = useSession();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [walletAddress, setWalletAddress] = useState('');

  const handleLogin = async () => {
    try {
      setLoading(true);
      setError('');
      await loginWithWallet(walletAddress);
    } catch (e: unknown) {
      setError((e as Error)?.message || 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="wallet-login-container">
      {error && <Error message={error} title="Wallet Connection Error" hideBackButton />}
      <input
        type="text"
        value={walletAddress}
        onChange={(e) => setWalletAddress(e.target.value)}
        placeholder="Enter wallet address"
      />
      <Button
        onPress={handleLogin}
        disabled={!walletAddress || loading}
        label={loading ? "Connecting..." : "Connect Wallet"}
      >
        <></>
      </Button>
    </div>
  );
};
