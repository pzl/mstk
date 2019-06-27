/*

Usage:

To create a general use logger, call logger.New(json). The argument is a boolean for whether the initial formatter should be JSON or not. Then it is just a pre-configured logrus instance.


If there are cases, where you have lines to log, but don't know whether logs should be JSON or not, you can use a BufferedLogger. This holds log entries in memory until such time that the format can be determined, and the old log entries are flushed. See NewBuffered() for more.


Times are in UTC.

*/
package logger
