package dao

import (
	"context"
	"fmt"

	"github.com/content-services/content-sources-backend/pkg/clients/candlepin_client"
	"github.com/content-services/content-sources-backend/pkg/clients/pulp_client"
	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/content-services/content-sources-backend/pkg/models"
	"github.com/labstack/gommon/random"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type domainDaoImpl struct {
	db         *gorm.DB
	pulpClient pulp_client.PulpGlobalClient
	cpClient   candlepin_client.CandlepinClient
}

func GetDomainDao(db *gorm.DB,
	pulpClient pulp_client.PulpGlobalClient,
	candlepinClient candlepin_client.CandlepinClient) DomainDao {
	// Return DAO instance
	return domainDaoImpl{
		db:         db,
		pulpClient: pulpClient,
		cpClient:   candlepinClient,
	}
}

func (dDao domainDaoImpl) FetchOrCreateDomain(ctx context.Context, orgId string) (string, error) {
	dName, err := dDao.Fetch(ctx, orgId)
	if err != nil {
		return "", err
	} else if dName != "" {
		return dName, nil
	}
	return dDao.Create(ctx, orgId)
}

func (dDao domainDaoImpl) Create(ctx context.Context, orgId string) (string, error) {
	name := fmt.Sprintf("cs-%v", random.New().String(10, random.Hex))
	if orgId == config.RedHatOrg {
		name = config.RedHatDomainName
	} else if orgId == config.CommunityOrg {
		name = config.CommunityDomainName
	}

	toCreate := models.Domain{
		DomainName: name,
		OrgId:      orgId,
	}
	result := dDao.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "org_id"}},
		DoNothing: true,
	}).Create(&toCreate)

	if result.Error != nil {
		return "", result.Error
	} else {
		return dDao.Fetch(ctx, orgId)
	}
}

func (dDao domainDaoImpl) Fetch(ctx context.Context, orgId string) (string, error) {
	var found []models.Domain
	result := dDao.db.WithContext(ctx).Where("org_id = ?", orgId).Find(&found)
	if result.Error != nil {
		return "", result.Error
	}
	if len(found) != 1 {
		return "", nil
	}
	return found[0].DomainName, nil
}

func (dDao domainDaoImpl) List(ctx context.Context) ([]models.Domain, error) {
	var domains []models.Domain
	result := dDao.db.WithContext(ctx).Table("domains").Find(&domains)
	if result.Error != nil {
		return nil, result.Error
	}
	return domains, nil
}

func (dDao domainDaoImpl) Delete(ctx context.Context, orgID string, domainName string) error {
	var domain models.Domain
	result := dDao.db.WithContext(ctx).Where("domain_name = ? AND org_id = ?", domainName, orgID).Delete(&domain)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
