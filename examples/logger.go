package examples

import "github.com/rs/zerolog"

type IamLogger struct {
	logger zerolog.Logger
}

func (l IamLogger) Debugf(f string, v ...interface{}) {
	l.logger.Debug().Msgf(f, v...)
}

func (l IamLogger) Infof(f string, v ...interface{}) {
	l.logger.Info().Msgf(f, v...)
}

func (l IamLogger) Warningf(f string, v ...interface{}) {
	l.logger.Warn().Msgf(f, v...)
}

func (l IamLogger) Errorf(f string, v ...interface{}) {
	l.logger.Error().Msgf(f, v...)
}
