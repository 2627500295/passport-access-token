import passport from 'passport-strategy';
import { Request } from 'express';
import {StrategyOptions, VerifiedCallback, VerifyCallback, VerifyCallbackWithRequest, FromRequestFunction} from './interfaces';

/**
 * Creates an instance of `Strategy`.
 *
 * @class
 * @constructor
 *
 * @param [options] - 选项
 * @param [options.fromRequest] - 从请求处理
 * @param [options.passReqToCallback] - 当 `true` 时，`request` 是 `verify` 回调的第一个参数 (default: `false`)
 * @param {Function} verify - 验证函数
 *
 * @example
 *
 * ```
 * const strategyOptions = {};
 *
 * function validate(token, done) {
 *   User.findByToken({ token }, (err, user) => {
 *     if (err) return done(err);
 *     if (!user) return done(null, false);
 *     return done(null, user);
 *   });
 * }
 *
 * passport.use(new Strategy(strategyOptions, validate));
 * ```
 *
 * @public
 *
 */
export class Strategy extends passport.Strategy {
  /**
   * 名称
   */
  public name = 'access-token';

  /**
   * 将 Request 传递给回调
   */
  private readonly passReqToCallback: boolean;

  /**
   * From Request
   *
   * @private
   */
  private readonly fromRequest: FromRequestFunction;

  /**
   * 验证函数
   */
  private readonly verify: any;

  /**
   * 构造函数
   *
   * @param options - 选项
   * @param verify - 验证函数
   *
   * @constructor
   * @public
   */
  // public constructor(verify?: Verify);
  // public constructor(options: StrategyOptions, verify?: Verify);
  // public constructor(options: Verify | StrategyOptions, verify?: Verify)
  public constructor(options: StrategyOptions, verify?: VerifyCallback)
  public constructor(options: StrategyOptions, verify?: VerifyCallbackWithRequest)
  public constructor(options: StrategyOptions, verify?: any){
    super();

    this.verify = verify;
    if (!verify) {
      throw new TypeError('Strategy requires a verify callback');
    }

    this.fromRequest = options.fromRequest;
    if (!this.fromRequest) {
      throw new TypeError('Strategy requires a function to retrieve from requests (see option fromRequest)');
    }

    this.passReqToCallback = options.passReqToCallback ?? false;
  }

  public authenticate(request: Request): void {
    const token = this.fromRequest(request);

    if (!token) {
      return this.fail(new Error("No auth token"),401);
    }

    const verified: VerifiedCallback = (error: any, user?: any, info?: any): void => {
      if (error) return this.error(error);
      if (!user) return this.fail(info, 401);
      return this.success(user, info);
    };

    try {
      if (this.passReqToCallback) {
        return this.verify(request, token, verified);
      }

      return this.verify(token, verified);
    } catch (ex: unknown) {
      return this.error(ex as Error);
    }
  }
}
