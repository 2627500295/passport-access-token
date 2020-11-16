import {FromRequestFunction} from './from-request-function.interface';

export interface StrategyOptions {
  /**
   * From Request
   */
  fromRequest: FromRequestFunction;

  /**
   * 将 Request 传递给回调
   */
  passReqToCallback?: boolean;
}
