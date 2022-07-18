import { u8, u16, i64 } from "./diplomat-runtime"
import { FFIError } from "./diplomat-runtime"
import { PickyError } from "./PickyError";

/**

 * UTC date and time.
 */
export class UtcDate {

  /**
   */
  static new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8): UtcDate | undefined;

  /**
   */
  static ymd(year: u16, month: u8, day: u8): UtcDate | undefined;

  /**
   */
  static now(): UtcDate;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_timestamp(timestamp: i64): UtcDate | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_timestamp(): i64 | never;

  /**
   */
  get_month(): u8;

  /**
   */
  get_day(): u8;

  /**
   */
  get_hour(): u8;

  /**
   */
  get_minute(): u8;

  /**
   */
  get_second(): u8;

  /**
   */
  get_year(): u16;
}
