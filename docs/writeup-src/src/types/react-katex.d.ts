// Type declarations for untyped packages
declare module 'react-katex' {
  import { FC } from 'react';
  interface KatexProps {
    math: string;
    block?: boolean;
    errorColor?: string;
    renderError?: (error: Error | TypeError) => React.ReactNode;
    settings?: Record<string, unknown>;
  }
  export const InlineMath: FC<KatexProps>;
  export const BlockMath: FC<KatexProps>;
}
