package sources

import (
	"context"
	"github.com/RMS2D/omnomfeeds/internal/models"
)

type Source interface {
	Name() string
	Type() string
	Fetch(ctx context.Context) ([]models.Article, error)
}
