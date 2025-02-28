package jobs

import (
	"context"

	"github.com/content-services/content-sources-backend/pkg/dao"
	"github.com/content-services/content-sources-backend/pkg/db"
	"github.com/content-services/content-sources-backend/pkg/pulp_client"
	"github.com/content-services/content-sources-backend/pkg/utils"
	zest "github.com/content-services/zest/release/v2024"
	"github.com/rs/zerolog/log"
)

func UpdateDomainDescription() {
	err := db.Connect()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}

	daoReg := dao.GetDaoRegistry(db.DB)
	ctx := context.Background()

	domains, err := daoReg.Domain.List(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to list domains")
	}
	for _, domain := range domains {
		pulpHref, err := pulp_client.GetGlobalPulpClient().LookupDomain(ctx, domain.DomainName)
		if err != nil {
			log.Error().Err(err).Msg("failed to lookup pulp domain")
		}

		err = pulp_client.GetGlobalPulpClient().UpdateDomain(ctx, pulpHref, zest.PatchedDomain{
			Description: *zest.NewNullableString(utils.Ptr("content-sources")),
		})
		if err != nil {
			log.Error().Err(err).Msg("failed to update domain description")
		}
	}
}
