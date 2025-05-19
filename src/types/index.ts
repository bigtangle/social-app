export interface SessionAccount {
  did: string;
  handle: string;
  service: string;
  accessJwt: string;
  refreshJwt: string;
  email?: string;
  emailConfirmed?: boolean;
  emailAuthFactor?: boolean;
  status?: 'active' | 'takendown' | 'deactivated';
  signupQueued?: boolean;
}

export interface Profile {
  did: string;
  handle: string;
  displayName?: string;
  description?: string;
  avatar?: string;
  banner?: string;
  followersCount?: number;
  followsCount?: number;
  postsCount?: number;
  viewer?: {
    following?: string;
    followedBy?: string;
  };
}

export interface Post {
  uri: string;
  cid: string;
  author: Profile;
  record: {
    text: string;
    createdAt: string;
  };
  embed?: Record<string, unknown>;
  replyCount?: number;
  repostCount?: number;
  likeCount?: number;
  indexedAt: string;
}
