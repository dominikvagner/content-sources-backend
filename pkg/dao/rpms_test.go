package dao

import (
	"context"
	"strings"
	"testing"

	"github.com/content-services/content-sources-backend/pkg/api"
	"github.com/content-services/content-sources-backend/pkg/clients/roadmap_client"
	"github.com/content-services/content-sources-backend/pkg/config"
	ce "github.com/content-services/content-sources-backend/pkg/errors"
	"github.com/content-services/content-sources-backend/pkg/models"
	"github.com/content-services/content-sources-backend/pkg/seeds"
	"github.com/content-services/content-sources-backend/pkg/utils"
	"github.com/content-services/tang/pkg/tangy"
	"github.com/content-services/yummy/pkg/yum"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type RpmSuite struct {
	*DaoSuite
	repoConfig        *models.RepositoryConfiguration
	repo              *models.Repository
	repoPrivate       *models.Repository
	mockRoadmapClient *roadmap_client.MockRoadmapClient
}

func (s *RpmSuite) SetupTest() {
	s.DaoSuite.SetupTest()

	repo := repoPublicTest.DeepCopy()
	if err := s.tx.Create(repo).Error; err != nil {
		s.FailNow("Preparing Repository record: %w", err)
	}
	s.repo = repo

	repoPrivate := repoPrivateTest.DeepCopy()
	if err := s.tx.Create(repoPrivate).Error; err != nil {
		s.FailNow("Preparing private Repository record: %w", err)
	}
	s.repoPrivate = repoPrivate

	repoConfig := repoConfigTest1.DeepCopy()
	repoConfig.RepositoryUUID = repo.Base.UUID
	if err := s.tx.Create(repoConfig).Error; err != nil {
		s.FailNow("Preparing RepositoryConfiguration record: %w", err)
	}
	s.repoConfig = repoConfig
}

func TestRpmSuite(t *testing.T) {
	m := DaoSuite{}
	r := RpmSuite{DaoSuite: &m, mockRoadmapClient: roadmap_client.NewMockRoadmapClient(t)}
	suite.Run(t, &r)
}

const (
	scenario0 int = iota
	scenario3
	scenarioUnderThreshold
	scenarioThreshold
	scenarioOverThreshold
)

func (s *RpmSuite) TestRpmList() {
	var err error
	t := s.Suite.T()

	// Prepare RepositoryRpm records
	rpm1 := repoRpmTest1.DeepCopy()
	rpm2 := repoRpmTest2.DeepCopy()
	dao := GetRpmDao(s.tx, s.mockRoadmapClient)

	err = s.tx.Create(&rpm1).Error
	assert.NoError(t, err)
	err = s.tx.Create(&rpm2).Error
	assert.NoError(t, err)
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: s.repo.Base.UUID,
		RpmUUID:        rpm1.Base.UUID,
	}).Error
	assert.NoError(t, err)
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: s.repo.Base.UUID,
		RpmUUID:        rpm2.Base.UUID,
	}).Error
	assert.NoError(t, err)

	var repoRpmList api.RepositoryRpmCollectionResponse
	var count int64
	repoRpmList, count, err = dao.List(context.Background(), orgIDTest, s.repoConfig.Base.UUID, 10, 0, "", "")
	assert.NoError(t, err)
	assert.Equal(t, count, int64(2))
	assert.Equal(t, repoRpmList.Meta.Count, count)
	assert.Equal(t, repoRpmList.Data[0].Name, repoRpmTest2.Name) // Asserts name:asc by default

	repoRpmList, count, err = dao.List(context.Background(), orgIDTest, s.repoConfig.Base.UUID, 10, 0, "test-package", "")
	assert.NoError(t, err)
	assert.Equal(t, count, int64(1))
	assert.Equal(t, repoRpmList.Meta.Count, count)

	repoRpmList, count, err = dao.List(context.Background(), orgIDTest, s.repoConfig.Base.UUID, 10, 0, "", "name:desc")
	assert.NoError(t, err)
	assert.Equal(t, count, int64(2))
	assert.Equal(t, repoRpmList.Data[0].Name, repoRpmTest1.Name) // Asserts name:desc

	repoRpmList, count, err = dao.List(context.Background(), orgIDTest, s.repoConfig.Base.UUID, 10, 0, "non-existing-repo", "")
	assert.NoError(t, err)
	assert.Equal(t, count, int64(0))
}

func (s *RpmSuite) TestRpmListRedHatRepositories() {
	var err error
	t := s.Suite.T()

	redHatRepo := repoPublicTest.DeepCopy()
	redHatRepo.URL = "https://www.public.redhat.com"
	if err := s.tx.Create(redHatRepo).Error; err != nil {
		s.FailNow("Preparing Repository record: %w", err)
	}

	redhatRepoConfig := repoConfigTest1.DeepCopy()
	redhatRepoConfig.OrgID = config.RedHatOrg
	redhatRepoConfig.Name = "Demo Redhat Repository Config"
	redhatRepoConfig.RepositoryUUID = redHatRepo.Base.UUID
	if err := s.tx.Create(redhatRepoConfig).Error; err != nil {
		s.FailNow("Preparing RepositoryConfiguration record: %w", err)
	}

	// Prepare RepositoryRpm records
	rpm1 := repoRpmTest1.DeepCopy()
	rpm2 := repoRpmTest2.DeepCopy()
	dao := GetRpmDao(s.tx, s.mockRoadmapClient)

	err = s.tx.Create(&rpm1).Error
	assert.NoError(t, err)
	err = s.tx.Create(&rpm2).Error
	assert.NoError(t, err)

	// Add one red hat repo
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: redHatRepo.Base.UUID,
		RpmUUID:        rpm1.Base.UUID,
	}).Error
	assert.NoError(t, err)

	// Add one regular repository
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: s.repo.Base.UUID,
		RpmUUID:        rpm2.Base.UUID,
	}).Error

	assert.NoError(t, err)

	var repoRpmList api.RepositoryRpmCollectionResponse
	var count int64

	// Check red hat repo package (matched "-1" orgID)
	repoRpmList, count, err = dao.List(context.Background(), "ThisOrgIdWontMatter", redhatRepoConfig.Base.UUID, 10, 0, "", "")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, repoRpmList.Meta.Count, count)
	assert.Equal(t, repoRpmTest1.Name, repoRpmList.Data[0].Name) // Asserts name:asc by default

	// Check custom repo package (checks orgId)
	repoRpmList, count, err = dao.List(context.Background(), orgIDTest, s.repoConfig.Base.UUID, 10, 0, "", "")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, repoRpmList.Meta.Count, count)
	assert.Equal(t, repoRpmTest2.Name, repoRpmList.Data[0].Name) // Asserts name:asc by default
}

func (s *RpmSuite) TestRpmListCommunityRepositories() {
	var err error
	t := s.Suite.T()

	communityRepo := repoPublicTest.DeepCopy()
	communityRepo.URL = "https://www.public.redhat.com"
	if err := s.tx.Create(communityRepo).Error; err != nil {
		s.FailNow("Preparing Repository record: %w", err)
	}

	communityRepoConfig := repoConfigTest1.DeepCopy()
	communityRepoConfig.OrgID = config.CommunityOrg
	communityRepoConfig.Name = "Demo Community Repository Config"
	communityRepoConfig.RepositoryUUID = communityRepo.Base.UUID
	if err := s.tx.Create(communityRepoConfig).Error; err != nil {
		s.FailNow("Preparing RepositoryConfiguration record: %w", err)
	}

	// Prepare RepositoryRpm records
	rpm1 := repoRpmTest1.DeepCopy()
	rpm2 := repoRpmTest2.DeepCopy()
	dao := GetRpmDao(s.tx, s.mockRoadmapClient)

	err = s.tx.Create(&rpm1).Error
	assert.NoError(t, err)
	err = s.tx.Create(&rpm2).Error
	assert.NoError(t, err)

	// Add one red hat repo
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: communityRepo.Base.UUID,
		RpmUUID:        rpm1.Base.UUID,
	}).Error
	assert.NoError(t, err)

	// Add one regular repository
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: s.repo.Base.UUID,
		RpmUUID:        rpm2.Base.UUID,
	}).Error

	assert.NoError(t, err)

	var repoRpmList api.RepositoryRpmCollectionResponse
	var count int64

	// Check red hat repo package (matched "-1" orgID)
	repoRpmList, count, err = dao.List(context.Background(), "ThisOrgIdWontMatter", communityRepoConfig.Base.UUID, 10, 0, "", "")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, repoRpmList.Meta.Count, count)
	assert.Equal(t, repoRpmTest1.Name, repoRpmList.Data[0].Name) // Asserts name:asc by default

	// Check custom repo package (checks orgId)
	repoRpmList, count, err = dao.List(context.Background(), orgIDTest, s.repoConfig.Base.UUID, 10, 0, "", "")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, repoRpmList.Meta.Count, count)
	assert.Equal(t, repoRpmTest2.Name, repoRpmList.Data[0].Name) // Asserts name:asc by default
}

func (s *RpmSuite) TestRpmListRepoNotFound() {
	t := s.Suite.T()
	dao := GetRpmDao(s.tx, s.mockRoadmapClient)

	_, count, err := dao.List(context.Background(), orgIDTest, uuid.NewString(), 10, 0, "", "")
	assert.Equal(t, count, int64(0))
	assert.Error(t, err)
	daoError, ok := err.(*ce.DaoError)
	assert.True(t, ok)
	assert.True(t, daoError.NotFound)

	rpm1 := repoRpmTest1.DeepCopy()
	err = s.tx.Create(&rpm1).Error
	assert.NoError(t, err)
	err = s.tx.Create(&models.RepositoryRpm{
		RepositoryUUID: s.repo.Base.UUID,
		RpmUUID:        rpm1.Base.UUID,
	}).Error
	assert.NoError(t, err)

	_, count, err = dao.List(context.Background(), seeds.RandomOrgId(), s.repoConfig.Base.UUID, 10, 0, "", "")
	assert.Equal(t, count, int64(0))
	assert.Error(t, err)
	daoError, ok = err.(*ce.DaoError)
	assert.True(t, ok)
	assert.True(t, daoError.NotFound)
}

func (s *RpmSuite) TestRpmSearch() {
	var err error
	t := s.Suite.T()
	tx := s.tx

	epelUrl := "https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/"
	epelRpm := models.Rpm{
		Name:     "epel-package-foo",
		Arch:     "x86_64",
		Version:  "1",
		Release:  "2",
		Epoch:    0,
		Summary:  "epel summary",
		Checksum: "abcdefg",
	}
	s.addRepositoryRpm(epelUrl, epelRpm)

	urls, uuids := s.prepRpms()
	// Add module with same name as package
	s.prepModule(uuids[0], "demo-package", "0", "123")
	s.prepModule(uuids[0], "demo-package", "0", "001")
	s.prepModule(uuids[0], "demo-package", "1", "456")

	redHatRepo := repoPublicTest.DeepCopy()
	redHatRepo.URL = "https://www.public.redhat.com"
	urls = append(urls, redHatRepo.URL)
	if err := s.tx.Create(redHatRepo).Error; err != nil {
		s.FailNow("Preparing Repository record: %w", err)
	}

	redhatRepoConfig := repoConfigTest1.DeepCopy()
	redhatRepoConfig.OrgID = config.RedHatOrg
	redhatRepoConfig.Name = "Demo Redhat Repository Config"
	redhatRepoConfig.RepositoryUUID = redHatRepo.Base.UUID
	redhatRepoConfig.Versions = pq.StringArray{config.El9}
	if err := s.tx.Create(redhatRepoConfig).Error; err != nil {
		s.FailNow("Preparing RepositoryConfiguration record: %w", err)
	}

	rpmRh := repoRpmTest1.DeepCopy()
	rpmRh.Name = "test-package-rh"
	s.addRepositoryRpm(redHatRepo.URL, *rpmRh)

	config.Get().Clients.Roadmap.Server = "http://example.com"
	expectedRoadmap := roadmap_client.AppstreamsResponse{
		Meta: roadmap_client.Meta{},
		Data: []roadmap_client.AppstreamEntity{
			{
				Name:      "demo-package",
				Stream:    "0",
				StartDate: "01-01-01",
				EndDate:   "02-02-02",
				Impl:      "dnf_module",
			},
			{
				Name:      "demo-package",
				Stream:    "1",
				StartDate: "01-01-01",
				EndDate:   "02-02-02",
				Impl:      "dnf_module",
			},
			{
				Name:      "demo-package",
				StartDate: "01-01-01",
				EndDate:   "02-02-02",
				Impl:      "package",
			},
		},
	}
	s.mockRoadmapClient.On("GetAppstreams", context.Background()).Return(expectedRoadmap, 0, nil)

	expectedLifecycle := map[int]roadmap_client.LifecycleEntity{
		10: {
			Name:      "rhel",
			StartDate: "01-01-01",
			EndDate:   "02-02-02",
			Major:     10,
			Minor:     2,
		},
		9: {
			Name:      "rhel",
			StartDate: "01-01-01",
			EndDate:   "02-02-02",
			Major:     9,
			Minor:     2,
		},
		8: {
			Name:      "rhel",
			StartDate: "01-01-01",
			EndDate:   "02-02-02",
			Major:     8,
			Minor:     2,
		},
	}
	s.mockRoadmapClient.On("GetRhelLifecycleForLatestMajorVersions", context.Background()).Return(expectedLifecycle, nil)

	// Test Cases
	type TestCaseGiven struct {
		orgId string
		input api.ContentUnitSearchRequest
	}
	type TestCase struct {
		name     string
		given    TestCaseGiven
		expected []api.SearchRpmResponse
	}
	testCases := []TestCase{
		{
			name: "The returned items are ordered by epoch",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					Search: "",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
				{
					PackageName: "test-package",
					Summary:     "test-package Epoch",
				},
			},
		},
		{
			name: "The limit is applied correctly, and the order is respected",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					Search: "",
					Limit:  utils.Ptr(1),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Search for the url[2] private repository",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[2],
					},
					Search: "",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
				{
					PackageName: "test-package",
					Summary:     "test-package Epoch",
				},
			},
		},
		{
			name: "Search for a popular url",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						epelUrl,
					},
					Search: "epel-package-",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: epelRpm.Name,
					Summary:     epelRpm.Summary,
				},
			},
		},
		{
			name: "Search for url[0] and url[1] filtering for %%demo-%% packages and it returns 1 entry",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					Search: "demo-",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Search for url[0] and url[1] filtering for %%demo-%% packages testing case insensitivity and it returns 1 entry",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					Search: "Demo-",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Search for uuid[0] filtering for %%demo-%% packages and it returns 1 entry",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					UUIDs: []string{
						uuids[0],
					},
					Search: "demo-",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Search for (uuid[0] or URL) and filtering for demo-%% packages and it returns 1 entry",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					UUIDs: []string{
						uuids[0],
					},
					Search: "demo-",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Test Default limit parameter",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					UUIDs: []string{
						uuids[0],
					},
					Search: "demo-",
					Limit:  nil,
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Test maximum limit parameter",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					UUIDs: []string{
						uuids[0],
					},
					Search: "demo-",
					Limit:  utils.Ptr(api.ContentUnitSearchRequestLimitMaximum * 2),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Check sub-string search",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					UUIDs: []string{
						uuids[0],
					},
					Search: "mo-pack",
					Limit:  utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{},
		},
		{
			name: "Exact matched items are returned",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					Search:     "package",
					ExactNames: []string{"demo-package"},
					Limit:      utils.Ptr(50),
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
				},
			},
		},
		{
			name: "Module info is added and correct if requested",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					UUIDs: []string{
						uuids[0],
					},
					Search:                "demo-package",
					Limit:                 utils.Ptr(50),
					IncludePackageSources: true,
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "demo-package",
					Summary:     "demo-package Epoch",
					PackageSources: []api.PackageSourcesResponse{
						{
							Type:        "module",
							Name:        "demo-package",
							Stream:      "0",
							Context:     "context",
							Arch:        "x86_64",
							Version:     "123",
							Description: "desc",
							StartDate:   "01-01-01",
							EndDate:     "02-02-02",
						},
						{
							Type:        "module",
							Name:        "demo-package",
							Stream:      "1",
							Context:     "context",
							Arch:        "x86_64",
							Version:     "456",
							Description: "desc",
							StartDate:   "01-01-01",
							EndDate:     "02-02-02",
						},
						{
							Type:      "package",
							Name:      "demo-package",
							StartDate: "01-01-01",
							EndDate:   "02-02-02",
						},
					},
				},
			},
		},
		{
			name: "Package sources correctly get rhel eol",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.ContentUnitSearchRequest{
					URLs: []string{
						urls[3],
					},
					Search:                "test-package-rh",
					Limit:                 utils.Ptr(50),
					IncludePackageSources: true,
				},
			},
			expected: []api.SearchRpmResponse{
				{
					PackageName: "test-package-rh",
					Summary:     "Test package summary",
					PackageSources: []api.PackageSourcesResponse{
						{
							Type:    "package",
							Name:    "test-package-rh",
							EndDate: "02-02-02",
						},
					},
				},
			},
		},
	}

	// Running all the test cases
	dao := GetRpmDao(tx, s.mockRoadmapClient)
	for _, caseTest := range testCases {
		t.Log(caseTest.name)
		var searchRpmResponse []api.SearchRpmResponse
		searchRpmResponse, err = dao.Search(context.Background(), caseTest.given.orgId, caseTest.given.input)
		require.NoError(t, err)
		assert.Equal(t, len(caseTest.expected), len(searchRpmResponse), "TestCase: %v failed expected response size", caseTest.name)
		for i, expected := range caseTest.expected {
			if i < len(searchRpmResponse) {
				assert.Equal(t, expected.PackageName, searchRpmResponse[i].PackageName, "TestCase: %v; expectedIndex: %i", caseTest.name, i)
				assert.Contains(t, searchRpmResponse[i].Summary, expected.Summary, "TestCase: %v; expectedIndex: %i", caseTest.name, i)
			}
			if expected.PackageSources != nil {
				assert.Equal(t, expected.PackageSources, searchRpmResponse[i].PackageSources, "TestCase: %v; expectedIndex: %i", caseTest.name, i)
			}
		}
	}

	// ensure errors returned for invalid repo uuid / url
	_, err = dao.Search(context.Background(), "fake-org", api.ContentUnitSearchRequest{
		UUIDs: []string{
			"fake-uuid",
		},
		Search: "fake-package",
		Limit:  utils.Ptr(50),
	})
	assert.Error(t, err)
	_, err = dao.Search(context.Background(), "fake-org", api.ContentUnitSearchRequest{
		URLs: []string{
			"https://fake-url.com",
		},
		Search: "fake-package",
		Limit:  utils.Ptr(50),
	})
	assert.Error(t, err)
}

// func (s *RpmSuite) randomPackageName(size int) string {
func randomPackageName(size int) string {
	const lookup string = "0123456789abcdefghijklmnopqrstuvwxyz"
	return seeds.RandStringWithChars(size, lookup)
}

// func (s *RpmSuite) randomHexadecimal(size int) string {
func randomHexadecimal(size int) string {
	const lookup string = "0123456789abcdef"
	return seeds.RandStringWithChars(size, lookup)
}

// func (s *RpmSuite) randomYumPackage() yum.Package {
func randomYumPackage(pkg *yum.Package) {
	if pkg == nil {
		return
	}
	pkgName := randomPackageName(32)
	pkg.Name = pkgName
	pkg.Arch = "x86_64"
	pkg.Summary = pkgName + " summary"
	pkg.Version = yum.Version{
		Version: "1.0.0",
		Release: "dev",
		Epoch:   0,
	}
	pkg.Type = "rpm"
	pkg.Checksum = yum.Checksum{
		Type:  "sha256",
		Value: randomHexadecimal(64),
	}
}

func makeYumPackage(size int) []yum.Package {
	var pkgs []yum.Package = []yum.Package{}

	if size < 0 {
		panic("size can not be a negative number")
	}

	if size == 0 {
		return pkgs
	}

	pkgs = make([]yum.Package, size)
	for i := 0; i < size; i++ {
		randomYumPackage(&pkgs[i])
	}

	return pkgs
}

func (s *RpmSuite) prepareScenarioRpms(scenario int, limit int) []yum.Package {
	s.db.CreateBatchSize = limit

	switch scenario {
	case scenario0:
		{
			return makeYumPackage(0)
		}
	case scenario3:
		// The reason of this scenario is to make debugging easier
		{
			return makeYumPackage(3)
		}
	case scenarioUnderThreshold:
		{
			return makeYumPackage(limit - 1)
		}
	case scenarioThreshold:
		{
			return makeYumPackage(limit)
		}
	case scenarioOverThreshold:
		{
			return makeYumPackage(limit + 1)
		}
	default:
		{
			return makeYumPackage(0)
		}
	}
}

func (s *RpmSuite) TestRpmSearchError() {
	var err error
	t := s.Suite.T()
	tx := s.tx
	txSP := strings.ToLower("TestRpmSearchError")

	var searchRpmResponse []api.SearchRpmResponse
	dao := GetRpmDao(tx, s.mockRoadmapClient)
	// We are going to launch database operations that evoke errors, so we need to restore
	// the state previous to the error to let the test do more actions
	tx.SavePoint(txSP)

	searchRpmResponse, err = dao.Search(context.Background(), "", api.ContentUnitSearchRequest{Search: "", URLs: []string{"https:/noreturn.org"}, Limit: utils.Ptr(100)})
	require.Error(t, err)
	assert.Equal(t, int(0), len(searchRpmResponse))
	assert.Equal(t, err.Error(), "orgID cannot be an empty string")
	tx.RollbackTo(txSP)

	searchRpmResponse, err = dao.Search(context.Background(), orgIDTest, api.ContentUnitSearchRequest{Search: "", Limit: utils.Ptr(100)})
	require.Error(t, err)
	assert.Equal(t, int(0), len(searchRpmResponse))
	assert.Equal(t, err.Error(), "must contain at least 1 URL or 1 UUID")
	tx.RollbackTo(txSP)
}

type TestInsertForRepositoryCase struct {
	given    int
	expected string
}

var testCases []TestInsertForRepositoryCase = []TestInsertForRepositoryCase{
	{
		given:    scenario0,
		expected: "",
	},
	{
		given:    scenario3,
		expected: "",
	},
	{
		given:    scenarioUnderThreshold,
		expected: "",
	},
	{
		given:    scenarioThreshold,
		expected: "",
	},
	{
		given:    scenarioOverThreshold,
		expected: "",
	},
}

func (s *RpmSuite) genericInsertForRepository(testCase TestInsertForRepositoryCase) {
	t := s.Suite.T()
	tx := s.tx

	dao := GetRpmDao(tx, s.mockRoadmapClient)

	p := s.prepareScenarioRpms(testCase.given, 10)
	records, err := dao.InsertForRepository(context.Background(), s.repo.Base.UUID, p)

	var rpmCount int = 0
	tx.Select("count(*) as rpm_count").
		Table(models.TableNameRpm).
		Joins("inner join "+models.TableNameRpmsRepositories+" on rpms.uuid = "+models.TableNameRpmsRepositories+".rpm_uuid").
		Where(models.TableNameRpmsRepositories+".repository_uuid = ?", s.repo.Base.UUID).
		Scan(&rpmCount)
	require.NoError(t, tx.Error)

	if testCase.expected != "" {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), testCase.expected)
	} else {
		assert.NoError(t, err)
		assert.Equal(t, int64(len(p)), records)
		assert.Equal(t, int64(rpmCount), records)
	}
}

func (s *RpmSuite) TestInsertForRepositoryScenario0() {
	s.genericInsertForRepository(testCases[scenario0])
}

func (s *RpmSuite) TestInsertForRepositoryScenario3() {
	s.genericInsertForRepository(testCases[scenario3])
}

func (s *RpmSuite) TestInsertForRepositoryScenarioUnderThreshold() {
	s.genericInsertForRepository(testCases[scenarioUnderThreshold])
}
func (s *RpmSuite) TestInsertForRepositoryScenarioThreshold() {
	s.genericInsertForRepository(testCases[scenarioThreshold])
}
func (s *RpmSuite) TestInsertForRepositoryScenarioOverThreshold() {
	s.genericInsertForRepository(testCases[scenarioOverThreshold])
}

func repoRpmCount(db *gorm.DB, repoUuid string) (int64, error) {
	var rpmCount int64
	err := db.
		Table("rpms").
		Joins("inner join repositories_rpms on repositories_rpms.rpm_uuid = rpms.uuid").
		Where("repositories_rpms.repository_uuid = ?", repoUuid).
		Count(&rpmCount).
		Error
	return rpmCount, err
}
func (s *RpmSuite) TestInsertForRepositoryWithExistingChecksums() {
	t := s.Suite.T()
	tx := s.tx
	var rpm_count int64

	pagedRpmInsertsLimit := 10
	groupCount := 5

	dao := GetRpmDao(tx, s.mockRoadmapClient)
	p := s.prepareScenarioRpms(scenarioThreshold, pagedRpmInsertsLimit)
	records, err := dao.InsertForRepository(context.Background(), s.repo.Base.UUID, p[0:groupCount])
	assert.NoError(t, err)
	assert.Equal(t, int64(len(p[0:groupCount])), records)
	rpm_count, err = repoRpmCount(tx, s.repo.UUID)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(p[0:groupCount])), rpm_count)

	records, err = dao.InsertForRepository(context.Background(), s.repo.Base.UUID, p[groupCount:])
	assert.NoError(t, err)
	assert.Equal(t, int64(len(p[groupCount:])), records)
	rpm_count, err = repoRpmCount(tx, s.repo.UUID)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(p[groupCount:])), rpm_count)

	records, err = dao.InsertForRepository(context.Background(), s.repoPrivate.Base.UUID, p[1:groupCount+1])
	assert.NoError(t, err)

	assert.Equal(t, int64(groupCount), records)
	rpm_count, err = repoRpmCount(tx, s.repoPrivate.UUID)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(p[1:groupCount+1])), rpm_count)

	records, err = dao.InsertForRepository(context.Background(), s.repoPrivate.Base.UUID, p[1:groupCount+1])
	assert.NoError(t, err)
	assert.Equal(t, int64(0), records) // Rpms have already been inserted

	rpm_count, err = repoRpmCount(tx, s.repoPrivate.Base.UUID)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(p[1:groupCount+1])), rpm_count)
}

func (s *RpmSuite) TestInsertForRepositoryWithLotsOfRpms() {
	t := s.Suite.T()
	tx := s.tx
	defer func() { DbInClauseLimit = 60000 }()
	DbInClauseLimit = 100
	rpms := makeYumPackage(333)
	dao := GetRpmDao(tx, s.mockRoadmapClient)
	records, err := dao.InsertForRepository(context.Background(), s.repo.Base.UUID, rpms)

	assert.NoError(t, err)
	assert.Equal(t, records, int64(333))
}

func (s *RpmSuite) TestInsertForRepositoryWithWrongRepoUUID() {
	t := s.Suite.T()
	tx := s.tx

	pagedRpmInsertsLimit := 100

	dao := GetRpmDao(tx, s.mockRoadmapClient)
	p := s.prepareScenarioRpms(scenario3, pagedRpmInsertsLimit)
	records, err := dao.InsertForRepository(context.Background(), uuid.NewString(), p)

	assert.Error(t, err)
	assert.Equal(t, records, int64(0))
}

func (s *RpmSuite) TestOrphanCleanup() {
	var err error
	var count int64

	t := s.Suite.T()

	// Prepare RepositoryRpm records
	rpm1 := repoRpmTest1.DeepCopy()
	dao := GetRpmDao(s.tx, s.mockRoadmapClient)

	err = s.tx.Create(&rpm1).Error
	assert.NoError(t, err)

	s.tx.Model(&rpm1).Where("uuid = ?", rpm1.UUID).Count(&count)
	assert.Equal(t, int64(1), count)

	err = dao.OrphanCleanup(context.Background())
	assert.NoError(t, err)

	s.tx.Model(&rpm1).Where("uuid = ?", rpm1.UUID).Count(&count)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Repeat the call for 'len(danglingRpmUuids) == 0'
	err = dao.OrphanCleanup(context.Background())
	assert.NoError(t, err)
}

func (s *RpmSuite) TestEmptyOrphanCleanup() {
	var count int64
	var countAfter int64
	dao := GetRpmDao(s.tx, s.mockRoadmapClient)
	err := dao.OrphanCleanup(context.Background()) // Clear out any existing orphaned rpms in the db
	assert.NoError(s.T(), err)

	s.tx.Model(&repoRpmTest1).Count(&count)
	err = dao.OrphanCleanup(context.Background())
	assert.NoError(s.T(), err)

	s.tx.Model(&repoRpmTest1).Count(&countAfter)
	assert.Equal(s.T(), count, countAfter)
}

func TestDifference(t *testing.T) {
	var (
		a []string
		b []string
		c []string
	)
	a = []string{"a", "b", "c"}
	b = []string{"b", "c", "d"}

	c = difference(a, b)
	assert.Equal(t, []string{"a"}, c)
}

func TestStringInSlice(t *testing.T) {
	var result bool
	slice := []string{"a", "b", "c"}

	result = stringInSlice("a", slice)
	assert.True(t, result)

	result = stringInSlice("d", slice)
	assert.False(t, result)
}

func TestFilteredConvert(t *testing.T) {
	givenYumPackages := []yum.Package{
		{
			Name: "package1",
			Arch: config.X8664,
			Type: "",
			Version: yum.Version{
				Version: "1.0.0",
				Release: "dev1",
				Epoch:   int32(0),
			},
			Checksum: yum.Checksum{
				Value: "e551de76480925a2745772787e18d2006c7546d86f12a59669dbd7b8a773204f",
				Type:  "sha256",
			},
		},
		{
			Name: "package2",
			Arch: config.AARCH64,
			Type: "",
			Version: yum.Version{
				Version: "1.0.0",
				Release: "dev2",
				Epoch:   int32(0),
			},
			Checksum: yum.Checksum{
				Value: "0835c9f490226b2d19e29be271c7eb3cf8174b95fd194cb40d5343ecd8e6069f",
				Type:  "sha256",
			},
		},
	}
	givenExcludeChecksums := []string{"0835c9f490226b2d19e29be271c7eb3cf8174b95fd194cb40d5343ecd8e6069f"}

	expected := []models.Rpm{
		{
			Name:     givenYumPackages[0].Name,
			Arch:     givenYumPackages[0].Arch,
			Version:  givenYumPackages[0].Version.Version,
			Release:  givenYumPackages[0].Version.Release,
			Epoch:    givenYumPackages[0].Version.Epoch,
			Checksum: givenYumPackages[0].Checksum.Value,
			Summary:  givenYumPackages[0].Summary,
		},
	}

	result := FilteredConvert(givenYumPackages, givenExcludeChecksums)
	assert.Equal(t, len(expected), len(result))
	assert.Equal(t, expected[0].Name, givenYumPackages[0].Name)
	assert.Equal(t, expected[0].Arch, givenYumPackages[0].Arch)
	assert.Equal(t, expected[0].Version, givenYumPackages[0].Version.Version)
	assert.Equal(t, expected[0].Release, givenYumPackages[0].Version.Release)
	assert.Equal(t, expected[0].Epoch, givenYumPackages[0].Version.Epoch)
	assert.Equal(t, expected[0].Checksum, givenYumPackages[0].Checksum.Value)
	assert.Equal(t, expected[0].Summary, givenYumPackages[0].Summary)
}

func mockTangy(t *testing.T) (*tangy.MockTangy, *tangy.Tangy) {
	originalTangy := config.Tang
	var mockTangy *tangy.MockTangy
	var realTangy tangy.Tangy
	mockTangy = tangy.NewMockTangy(t)
	realTangy = mockTangy
	config.Tang = &realTangy
	return mockTangy, originalTangy
}

func (s *RpmSuite) TestSearchRpmsForSnapshots() {
	orgId := seeds.RandomOrgId()
	mTangy, origTangy := mockTangy(s.T())
	defer func() { config.Tang = origTangy }()
	ctx := context.Background()

	hrefs := []string{"some_pulp_version_href"}
	expected := []tangy.RpmPackageSearch{{
		Name:    "Foodidly",
		Summary: "there was a great foo",
	}}

	// Create a repo config, and snapshot, update its version_href to expected href
	repoConfigs, err := seeds.SeedRepositoryConfigurations(s.tx, 2, seeds.SeedOptions{
		OrgID:     orgId,
		BatchSize: 0,
	})
	require.NoError(s.T(), err)
	repoConfig := repoConfigs[0]

	snaps, err := seeds.SeedSnapshots(s.tx, repoConfig.UUID, 1)
	require.NoError(s.T(), err)
	res := s.tx.Model(&models.Snapshot{}).Where("repository_configuration_uuid = ?", repoConfig.UUID).Update("version_href", hrefs[0])
	require.NoError(s.T(), res.Error)
	// Add module with same name as package
	s.prepModule(repoConfig.UUID, "Foodidly", "2", "1")

	// Add a second module with a higher version in a different repo
	s.prepModule(repoConfigs[1].UUID, "Foodidly", "2", "2")

	// pulpHrefs, request.Search, *request.Limit)
	mTangy.On("RpmRepositoryVersionPackageSearch", ctx, hrefs, "Foo", 55).Return(expected, nil)

	dao := GetRpmDao(s.tx, s.mockRoadmapClient)
	ret, err := dao.SearchSnapshotRpms(ctx, orgId, api.SnapshotSearchRpmRequest{
		UUIDs:  []string{snaps[0].UUID},
		Search: "Foo",
		Limit:  utils.Ptr(55),
	})
	require.NoError(s.T(), err)

	assert.Equal(s.T(), []api.SearchRpmResponse{{
		PackageName: expected[0].Name,
		Summary:     expected[0].Summary,
	}}, ret)

	config.Get().Clients.Roadmap.Server = "http://example.com"
	expectedRoadmap := roadmap_client.AppstreamsResponse{
		Meta: roadmap_client.Meta{},
		Data: []roadmap_client.AppstreamEntity{
			{
				Name:      "demo-package",
				Stream:    "0",
				StartDate: "01-01-01",
				EndDate:   "02-02-02",
				Impl:      "dnf_module",
			},
			{
				Name:      "demo-package",
				Stream:    "1",
				StartDate: "01-01-01",
				EndDate:   "02-02-02",
				Impl:      "dnf_module",
			},
			{
				Name:      "demo-package",
				StartDate: "01-01-01",
				EndDate:   "02-02-02",
				Impl:      "package",
			},
		},
	}
	s.mockRoadmapClient.On("GetAppstreams", context.Background()).Return(expectedRoadmap, 0, nil)

	// ensure module info is in response and correct if requested
	ret, err = dao.SearchSnapshotRpms(ctx, orgId, api.SnapshotSearchRpmRequest{
		UUIDs:                 []string{snaps[0].UUID},
		Search:                "Foo",
		Limit:                 utils.Ptr(55),
		IncludePackageSources: true,
	})
	require.NoError(s.T(), err)

	assert.Equal(s.T(), []api.SearchRpmResponse{{
		PackageName: expected[0].Name,
		Summary:     expected[0].Summary,
		PackageSources: []api.PackageSourcesResponse{
			{
				Type:        "module",
				Name:        "Foodidly",
				Stream:      "2",
				Context:     "context",
				Arch:        "x86_64",
				Version:     "1",
				Description: "desc",
			},
		},
	}}, ret)

	// ensure error returned for invalid snapshot uuid
	_, err = dao.SearchSnapshotRpms(ctx, orgId, api.SnapshotSearchRpmRequest{
		UUIDs: []string{
			"fake-uuid",
		},
		Search: "fake-package",
		Limit:  utils.Ptr(55),
	})
	assert.Error(s.T(), err)
}

func (s *RpmSuite) TestListRpmsAndErrataForSnapshots() {
	orgId := seeds.RandomOrgId()
	mTangy, origTangy := mockTangy(s.T())
	defer func() { config.Tang = origTangy }()
	ctx := context.Background()

	hrefs := []string{"some_pulp_version_href"}
	expected := []tangy.RpmListItem{{
		Name:    "Foodidly",
		Summary: "there was a great foo",
	}}

	// Create a repo config, and snapshot, update its version_href to expected href
	_, err := seeds.SeedRepositoryConfigurations(s.tx, 1, seeds.SeedOptions{
		OrgID:     orgId,
		BatchSize: 0,
	})
	require.NoError(s.T(), err)
	repoConfig := models.RepositoryConfiguration{}
	res := s.tx.Where("org_id = ?", orgId).First(&repoConfig)
	require.NoError(s.T(), res.Error)
	snaps, err := seeds.SeedSnapshots(s.tx, repoConfig.UUID, 1)
	require.NoError(s.T(), err)
	res = s.tx.Model(&models.Snapshot{}).Where("repository_configuration_uuid = ?", repoConfig.UUID).Update("version_href", hrefs[0])
	require.NoError(s.T(), res.Error)

	total := 5
	search := "wake"
	page := api.PaginationData{Limit: 3, Offset: 101}
	mTangy.On("RpmRepositoryVersionPackageList", ctx, hrefs, tangy.RpmListFilters{Name: search}, tangy.PageOptions{Offset: 101, Limit: 3}).Return(expected, total, nil)

	dao := GetRpmDao(s.tx, s.mockRoadmapClient)
	ret, totalRec, err := dao.ListSnapshotRpms(ctx, orgId, []string{snaps[0].UUID}, search, page)

	require.NoError(s.T(), err)

	assert.Equal(s.T(), total, totalRec)
	assert.Equal(s.T(), []api.SnapshotRpm{{
		Name:    expected[0].Name,
		Summary: expected[0].Summary,
	}}, ret)

	expectedErrataItem := []tangy.ErrataListItem{
		{
			ErrataId: "Foodidly",
			Summary:  "there was a great foo",
			Type:     "bugfix",
			CVEs:     []string{},
		},
		{
			ErrataId: "Foodidly2",
			Summary:  "there was another great foo",
			Type:     "security",
			CVEs:     []string{},
		},
	}

	page = api.PaginationData{Limit: 3, Offset: 101, SortBy: "type:asc"}
	mTangy.On("RpmRepositoryVersionErrataList", ctx, hrefs, tangy.ErrataListFilters{}, tangy.PageOptions{Offset: 101, Limit: 3, SortBy: "type:asc"}).Return(expectedErrataItem, total, nil)
	resp, totalRec, err := dao.ListSnapshotErrata(ctx, orgId, []string{snaps[0].UUID}, tangy.ErrataListFilters{}, page)

	require.NoError(s.T(), err)

	assert.Equal(s.T(), total, totalRec)
	assert.Equal(s.T(), []api.SnapshotErrata{
		{
			ErrataId: expectedErrataItem[0].ErrataId,
			Summary:  expectedErrataItem[0].Summary,
			Type:     expectedErrataItem[0].Type,
			CVEs:     expectedErrataItem[0].CVEs,
		},
		{
			ErrataId: expectedErrataItem[1].ErrataId,
			Summary:  expectedErrataItem[1].Summary,
			Type:     expectedErrataItem[1].Type,
			CVEs:     expectedErrataItem[1].CVEs,
		},
	}, resp)
}

func (s *RpmSuite) TestDetectRpms() {
	ctx := context.Background()
	var err error
	t := s.Suite.T()
	tx := s.tx

	urls, uuids := s.prepRpms()

	type TestCaseGiven struct {
		orgId string
		input api.DetectRpmsRequest
	}
	type TestCase struct {
		name     string
		given    TestCaseGiven
		expected api.DetectRpmsResponse
	}
	testCases := []TestCase{
		{
			name: "Correct packages are reported as found and missing in the requested repo URLs",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.DetectRpmsRequest{
					URLs: []string{
						urls[0],
						urls[1],
					},
					RpmNames: []string{"demo-package", "test-package", "fake-package"},
					Limit:    utils.Ptr(50),
				},
			},
			expected: api.DetectRpmsResponse{
				Found:   []string{"demo-package", "test-package"},
				Missing: []string{"fake-package"},
			},
		},
		{
			name: "Correct packages are reported as found and missing in the requested repo UUID",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.DetectRpmsRequest{
					UUIDs: []string{
						uuids[0],
					},
					RpmNames: []string{"test-package", "demo-package", "fake-package"},
					Limit:    utils.Ptr(50),
				},
			},
			expected: api.DetectRpmsResponse{
				Found:   []string{"demo-package", "test-package"},
				Missing: []string{"fake-package"},
			},
		},
		{
			name: "Correct packages are reported as found and missing in the requested repo UUID / URLs",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.DetectRpmsRequest{
					UUIDs: []string{
						uuids[0],
					},
					URLs: []string{
						urls[0],
						urls[1],
					},
					RpmNames: []string{"test-package", "demo-package", "fake-package"},
					Limit:    utils.Ptr(50),
				},
			},
			expected: api.DetectRpmsResponse{
				Found:   []string{"demo-package", "test-package"},
				Missing: []string{"fake-package"},
			},
		},
		{
			name: "No missing packages",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.DetectRpmsRequest{
					UUIDs: []string{
						uuids[0],
					},
					RpmNames: []string{"test-package", "demo-package"},
					Limit:    utils.Ptr(50),
				},
			},
			expected: api.DetectRpmsResponse{
				Found:   []string{"demo-package", "test-package"},
				Missing: []string{},
			},
		},
		{
			name: "No found packages",
			given: TestCaseGiven{
				orgId: orgIDTest,
				input: api.DetectRpmsRequest{
					UUIDs: []string{
						uuids[0],
					},
					RpmNames: []string{"fake-package"},
					Limit:    utils.Ptr(50),
				},
			},
			expected: api.DetectRpmsResponse{
				Found:   []string{},
				Missing: []string{"fake-package"},
			},
		},
	}

	// run through test cases
	dao := GetRpmDao(tx, s.mockRoadmapClient)
	for _, test := range testCases {
		var detectRpmsResponse *api.DetectRpmsResponse
		detectRpmsResponse, err = dao.DetectRpms(ctx, test.given.orgId, test.given.input)
		require.NoError(t, err)
		if detectRpmsResponse != nil {
			assert.Equal(t, test.expected.Found, detectRpmsResponse.Found)
			assert.Equal(t, test.expected.Missing, detectRpmsResponse.Missing)
		}
	}

	// ensure errors returned for invalid repo uuid / url
	_, err = dao.DetectRpms(ctx, "fake-org", api.DetectRpmsRequest{
		UUIDs: []string{
			"fake-uuid",
		},
		RpmNames: []string{"fake-package"},
		Limit:    utils.Ptr(50),
	})
	assert.Error(t, err)
	_, err = dao.DetectRpms(ctx, "fake-org", api.DetectRpmsRequest{
		URLs: []string{
			"https://fake-url.com",
		},
		RpmNames: []string{"fake-package"},
		Limit:    utils.Ptr(50),
	})
	assert.Error(t, err)
}

func (s *RpmSuite) addRepositoryRpm(url string, rpm models.Rpm) {
	t := s.Suite.T()
	tx := s.tx

	result := tx.Create(&rpm)
	assert.NoError(t, result.Error)

	repo := models.Repository{}
	result = tx.Model(models.Repository{}).Where("url = ?", url).First(&repo)
	assert.NoError(t, result.Error)

	// Create a orphaned repo if it doesn't already exist
	if repo.UUID == "" {
		result = tx.Create(&models.Repository{URL: url})
		assert.NoError(t, result.Error)
	}

	result = tx.Create(&models.RepositoryRpm{
		RepositoryUUID: repo.UUID,
		RpmUUID:        rpm.UUID,
	})
	assert.NoError(t, result.Error)
}

func (s *RpmSuite) prepRpms() ([]string, []string) {
	t := s.Suite.T()
	tx := s.tx

	// Prepare Rpm records
	urls := []string{
		"https://repo-test-package.org",
		"https://repo-demo-package.org",
		"https://repo-private-package.org",
	}
	rpms := make([]models.Rpm, 4)
	repoRpmTest1.DeepCopyInto(&rpms[0])
	repoRpmTest2.DeepCopyInto(&rpms[1])
	repoRpmTest1.DeepCopyInto(&rpms[2])
	repoRpmTest2.DeepCopyInto(&rpms[3])
	rpms[0].Name = "test-package"
	rpms[1].Name = "demo-package"
	rpms[2].Name = "test-package"
	rpms[3].Name = "demo-package"
	rpms[0].Epoch = 0
	rpms[1].Epoch = 0
	rpms[2].Epoch = 1
	rpms[3].Epoch = 1
	rpms[0].Summary = "test-package Epoch 0"
	rpms[1].Summary = "demo-package Epoch 0"
	rpms[2].Summary = "test-package Epoch 1"
	rpms[3].Summary = "demo-package Epoch 1"
	rpms[0].Checksum = "SHA256:" + uuid.NewString()
	rpms[1].Checksum = "SHA256:" + uuid.NewString()
	rpms[2].Checksum = "SHA256:" + uuid.NewString()
	rpms[3].Checksum = "SHA256:" + uuid.NewString()
	err := tx.Create(&rpms).Error
	require.NoError(t, err)

	// Prepare Repository records
	repositories := make([]models.Repository, 3)
	repoPublicTest.DeepCopyInto(&repositories[0])
	repoPublicTest.DeepCopyInto(&repositories[1])
	repoPublicTest.DeepCopyInto(&repositories[2])
	repositories[0].URL = urls[0]
	repositories[1].URL = urls[1]
	repositories[2].URL = urls[2]
	repositories[0].Public = true
	repositories[1].Public = true
	repositories[2].Public = false
	err = tx.Create(&repositories).Error
	require.NoError(t, err)

	// Prepare RepositoryConfiguration records
	repositoryConfigurations := make([]models.RepositoryConfiguration, 1)
	repoConfigTest1.DeepCopyInto(&repositoryConfigurations[0])
	repositoryConfigurations[0].Name = "private-repository-configuration"
	repositoryConfigurations[0].RepositoryUUID = repositories[2].Base.UUID
	err = tx.Create(&repositoryConfigurations).Error
	require.NoError(t, err)

	// Prepare relations repositories_rpms
	repositoriesRpms := make([]models.RepositoryRpm, 8)
	repositoriesRpms[0].RepositoryUUID = repositories[0].Base.UUID
	repositoriesRpms[0].RpmUUID = rpms[0].Base.UUID
	repositoriesRpms[1].RepositoryUUID = repositories[0].Base.UUID
	repositoriesRpms[1].RpmUUID = rpms[1].Base.UUID
	repositoriesRpms[2].RepositoryUUID = repositories[1].Base.UUID
	repositoriesRpms[2].RpmUUID = rpms[2].Base.UUID
	repositoriesRpms[3].RepositoryUUID = repositories[1].Base.UUID
	repositoriesRpms[3].RpmUUID = rpms[3].Base.UUID
	// Add rpms to private repository
	repositoriesRpms[4].RepositoryUUID = repositories[2].Base.UUID
	repositoriesRpms[4].RpmUUID = rpms[0].Base.UUID
	repositoriesRpms[5].RepositoryUUID = repositories[2].Base.UUID
	repositoriesRpms[5].RpmUUID = rpms[1].Base.UUID
	repositoriesRpms[6].RepositoryUUID = repositories[2].Base.UUID
	repositoriesRpms[6].RpmUUID = rpms[2].Base.UUID
	repositoriesRpms[7].RepositoryUUID = repositories[2].Base.UUID
	repositoriesRpms[7].RpmUUID = rpms[3].Base.UUID
	err = tx.Create(&repositoriesRpms).Error
	require.NoError(t, err)

	uuids := []string{
		repositoryConfigurations[0].Base.UUID,
	}

	return urls, uuids
}

func (s *RpmSuite) prepModule(repoConfigUUID string, name string, stream string, version string) {
	var repoConfig models.RepositoryConfiguration
	err := s.tx.Where("uuid = ?", repoConfigUUID).First(&repoConfig).Error
	require.NoError(s.T(), err)

	module := models.ModuleStream{
		Name:         name,
		Stream:       stream,
		Version:      version,
		Context:      "context",
		Arch:         "x86_64",
		Summary:      "summary",
		Description:  "desc",
		PackageNames: []string{name},
		HashValue:    uuid.NewString(),
	}
	err = s.tx.Create([]*models.ModuleStream{&module}).Error
	require.NoError(s.T(), err)

	repoUUID := repoConfig.RepositoryUUID
	err = s.tx.Create([]models.RepositoryModuleStream{
		{RepositoryUUID: repoUUID, ModuleStreamUUID: module.UUID},
	}).Error
	require.NoError(s.T(), err)
}

func (s *RpmSuite) TestListRpmsForTemplates() {
	orgId := seeds.RandomOrgId()
	mTangy, origTangy := mockTangy(s.T())
	defer func() { config.Tang = origTangy }()
	ctx := context.Background()

	hrefs := []string{"some_pulp_version_href"}
	expected := []tangy.RpmListItem{{
		Name:    "Foodidly",
		Summary: "there was a great foo",
	}}

	_, err := seeds.SeedRepositoryConfigurations(s.tx, 1, seeds.SeedOptions{
		OrgID:     orgId,
		BatchSize: 0,
	})
	require.NoError(s.T(), err)
	repoConfig := models.RepositoryConfiguration{}
	res := s.tx.Where("org_id = ?", orgId).First(&repoConfig)
	require.NoError(s.T(), res.Error)

	snaps, err := seeds.SeedSnapshots(s.tx, repoConfig.UUID, 1)
	require.NoError(s.T(), err)
	res = s.tx.Model(&models.Snapshot{}).Where("repository_configuration_uuid = ?", repoConfig.UUID).Update("version_href", hrefs[0])
	require.NoError(s.T(), res.Error)

	_, err = seeds.SeedTemplates(s.tx, 1, seeds.TemplateSeedOptions{OrgID: orgId, RepositoryConfigUUIDs: []string{repoConfig.UUID}, Snapshots: []models.Snapshot{snaps[0]}})
	require.NoError(s.T(), err)
	template := models.Template{}
	res = s.tx.Where("org_id = ?", orgId).First(&template)
	require.NoError(s.T(), res.Error)

	total := 5
	search := "wake"
	page := api.PaginationData{Limit: 3, Offset: 101}
	mTangy.On("RpmRepositoryVersionPackageList", ctx, hrefs, tangy.RpmListFilters{Name: search}, tangy.PageOptions{Offset: 101, Limit: 3}).Return(expected, total, nil)

	dao := GetRpmDao(s.tx, s.mockRoadmapClient)
	ret, totalRec, err := dao.ListTemplateRpms(ctx, orgId, template.UUID, search, page)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), total, totalRec)
	assert.Equal(s.T(), []api.SnapshotRpm{{
		Name:    expected[0].Name,
		Summary: expected[0].Summary,
	}}, ret)
}

func (s *RpmSuite) TestListErrataForTemplates() {
	orgId := seeds.RandomOrgId()
	mTangy, origTangy := mockTangy(s.T())
	defer func() { config.Tang = origTangy }()
	ctx := context.Background()

	hrefs := []string{"some_pulp_version_href"}

	// Create a repo config, and snapshot, update its version_href to expected href
	_, err := seeds.SeedRepositoryConfigurations(s.tx, 1, seeds.SeedOptions{
		OrgID:     orgId,
		BatchSize: 0,
	})
	require.NoError(s.T(), err)

	repoConfig := models.RepositoryConfiguration{}
	res := s.tx.Where("org_id = ?", orgId).First(&repoConfig)
	require.NoError(s.T(), res.Error)

	snaps, err := seeds.SeedSnapshots(s.tx, repoConfig.UUID, 1)
	require.NoError(s.T(), err)

	res = s.tx.Model(&models.Snapshot{}).Where("repository_configuration_uuid = ?", repoConfig.UUID).Update("version_href", hrefs[0])
	require.NoError(s.T(), res.Error)

	templates, err := seeds.SeedTemplates(s.tx, 1, seeds.TemplateSeedOptions{OrgID: orgId, RepositoryConfigUUIDs: []string{repoConfig.UUID}, Snapshots: []models.Snapshot{snaps[0]}})
	require.NoError(s.T(), err)
	template := templates[0]

	expectedErrataItem := []tangy.ErrataListItem{{
		ErrataId: "Foodidly",
		Summary:  "there was a great foo",
		CVEs:     []string{"CVE-1"},
	}}

	total := 5
	search := "wake"
	page := api.PaginationData{Limit: 3, Offset: 101}
	mTangy.On("RpmRepositoryVersionErrataList", ctx, hrefs, tangy.ErrataListFilters{Search: search}, tangy.PageOptions{Offset: 101, Limit: 3}).Return(expectedErrataItem, total, nil)

	dao := GetRpmDao(s.tx, s.mockRoadmapClient)
	resp, totalRec, err := dao.ListTemplateErrata(ctx, orgId, template.UUID, tangy.ErrataListFilters{Search: search}, page)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), total, totalRec)
	assert.Equal(s.T(), []api.SnapshotErrata{{
		ErrataId: expectedErrataItem[0].ErrataId,
		Summary:  expectedErrataItem[0].Summary,
		CVEs:     expectedErrataItem[0].CVEs,
	}}, resp)
}
