package iam_client

type Logger interface {
	Debugf(f string, v ...interface{})
	Infof(f string, v ...interface{})
	Warningf(f string, v ...interface{})
	Errorf(f string, v ...interface{})
}
