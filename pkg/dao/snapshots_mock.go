// Code generated by mockery. DO NOT EDIT.

package dao

import (
	context "context"

	api "github.com/content-services/content-sources-backend/pkg/api"
	models "github.com/content-services/content-sources-backend/pkg/models"
	mock "github.com/stretchr/testify/mock"
)

// MockSnapshotDao is an autogenerated mock type for the SnapshotDao type
type MockSnapshotDao struct {
	mock.Mock
}

// BulkDelete provides a mock function with given fields: ctx, uuids
func (_m *MockSnapshotDao) BulkDelete(ctx context.Context, uuids []string) []error {
	ret := _m.Called(ctx, uuids)

	if len(ret) == 0 {
		panic("no return value specified for BulkDelete")
	}

	var r0 []error
	if rf, ok := ret.Get(0).(func(context.Context, []string) []error); ok {
		r0 = rf(ctx, uuids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]error)
		}
	}

	return r0
}

// ClearDeletedAt provides a mock function with given fields: ctx, snapUUID
func (_m *MockSnapshotDao) ClearDeletedAt(ctx context.Context, snapUUID string) error {
	ret := _m.Called(ctx, snapUUID)

	if len(ret) == 0 {
		panic("no return value specified for ClearDeletedAt")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, snapUUID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Create provides a mock function with given fields: ctx, snap
func (_m *MockSnapshotDao) Create(ctx context.Context, snap *models.Snapshot) error {
	ret := _m.Called(ctx, snap)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.Snapshot) error); ok {
		r0 = rf(ctx, snap)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Delete provides a mock function with given fields: ctx, snapUUID
func (_m *MockSnapshotDao) Delete(ctx context.Context, snapUUID string) error {
	ret := _m.Called(ctx, snapUUID)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, snapUUID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Fetch provides a mock function with given fields: ctx, uuid
func (_m *MockSnapshotDao) Fetch(ctx context.Context, uuid string) (api.SnapshotResponse, error) {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for Fetch")
	}

	var r0 api.SnapshotResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (api.SnapshotResponse, error)); ok {
		return rf(ctx, uuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) api.SnapshotResponse); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(api.SnapshotResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, uuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchForRepoConfigUUID provides a mock function with given fields: ctx, repoConfigUUID
func (_m *MockSnapshotDao) FetchForRepoConfigUUID(ctx context.Context, repoConfigUUID string) ([]models.Snapshot, error) {
	ret := _m.Called(ctx, repoConfigUUID)

	if len(ret) == 0 {
		panic("no return value specified for FetchForRepoConfigUUID")
	}

	var r0 []models.Snapshot
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]models.Snapshot, error)); ok {
		return rf(ctx, repoConfigUUID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []models.Snapshot); ok {
		r0 = rf(ctx, repoConfigUUID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Snapshot)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, repoConfigUUID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchLatestSnapshot provides a mock function with given fields: ctx, repoConfigUUID
func (_m *MockSnapshotDao) FetchLatestSnapshot(ctx context.Context, repoConfigUUID string) (api.SnapshotResponse, error) {
	ret := _m.Called(ctx, repoConfigUUID)

	if len(ret) == 0 {
		panic("no return value specified for FetchLatestSnapshot")
	}

	var r0 api.SnapshotResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (api.SnapshotResponse, error)); ok {
		return rf(ctx, repoConfigUUID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) api.SnapshotResponse); ok {
		r0 = rf(ctx, repoConfigUUID)
	} else {
		r0 = ret.Get(0).(api.SnapshotResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, repoConfigUUID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchLatestSnapshotModel provides a mock function with given fields: ctx, repoConfigUUID
func (_m *MockSnapshotDao) FetchLatestSnapshotModel(ctx context.Context, repoConfigUUID string) (models.Snapshot, error) {
	ret := _m.Called(ctx, repoConfigUUID)

	if len(ret) == 0 {
		panic("no return value specified for FetchLatestSnapshotModel")
	}

	var r0 models.Snapshot
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (models.Snapshot, error)); ok {
		return rf(ctx, repoConfigUUID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) models.Snapshot); ok {
		r0 = rf(ctx, repoConfigUUID)
	} else {
		r0 = ret.Get(0).(models.Snapshot)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, repoConfigUUID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchSnapshotByVersionHref provides a mock function with given fields: ctx, repoConfigUUID, versionHref
func (_m *MockSnapshotDao) FetchSnapshotByVersionHref(ctx context.Context, repoConfigUUID string, versionHref string) (*api.SnapshotResponse, error) {
	ret := _m.Called(ctx, repoConfigUUID, versionHref)

	if len(ret) == 0 {
		panic("no return value specified for FetchSnapshotByVersionHref")
	}

	var r0 *api.SnapshotResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*api.SnapshotResponse, error)); ok {
		return rf(ctx, repoConfigUUID, versionHref)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *api.SnapshotResponse); ok {
		r0 = rf(ctx, repoConfigUUID, versionHref)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*api.SnapshotResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, repoConfigUUID, versionHref)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchSnapshotsByDateAndRepository provides a mock function with given fields: ctx, orgID, request
func (_m *MockSnapshotDao) FetchSnapshotsByDateAndRepository(ctx context.Context, orgID string, request api.ListSnapshotByDateRequest) (api.ListSnapshotByDateResponse, error) {
	ret := _m.Called(ctx, orgID, request)

	if len(ret) == 0 {
		panic("no return value specified for FetchSnapshotsByDateAndRepository")
	}

	var r0 api.ListSnapshotByDateResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, api.ListSnapshotByDateRequest) (api.ListSnapshotByDateResponse, error)); ok {
		return rf(ctx, orgID, request)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, api.ListSnapshotByDateRequest) api.ListSnapshotByDateResponse); ok {
		r0 = rf(ctx, orgID, request)
	} else {
		r0 = ret.Get(0).(api.ListSnapshotByDateResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, api.ListSnapshotByDateRequest) error); ok {
		r1 = rf(ctx, orgID, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchSnapshotsModelByDateAndRepository provides a mock function with given fields: ctx, orgID, request
func (_m *MockSnapshotDao) FetchSnapshotsModelByDateAndRepository(ctx context.Context, orgID string, request api.ListSnapshotByDateRequest) ([]models.Snapshot, error) {
	ret := _m.Called(ctx, orgID, request)

	if len(ret) == 0 {
		panic("no return value specified for FetchSnapshotsModelByDateAndRepository")
	}

	var r0 []models.Snapshot
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, api.ListSnapshotByDateRequest) ([]models.Snapshot, error)); ok {
		return rf(ctx, orgID, request)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, api.ListSnapshotByDateRequest) []models.Snapshot); ok {
		r0 = rf(ctx, orgID, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Snapshot)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, api.ListSnapshotByDateRequest) error); ok {
		r1 = rf(ctx, orgID, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FetchUnscoped provides a mock function with given fields: ctx, uuid
func (_m *MockSnapshotDao) FetchUnscoped(ctx context.Context, uuid string) (models.Snapshot, error) {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for FetchUnscoped")
	}

	var r0 models.Snapshot
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (models.Snapshot, error)); ok {
		return rf(ctx, uuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) models.Snapshot); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(models.Snapshot)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, uuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRepositoryConfigurationFile provides a mock function with given fields: ctx, orgID, snapshotUUID, isLatest
func (_m *MockSnapshotDao) GetRepositoryConfigurationFile(ctx context.Context, orgID string, snapshotUUID string, isLatest bool) (string, error) {
	ret := _m.Called(ctx, orgID, snapshotUUID, isLatest)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositoryConfigurationFile")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) (string, error)); ok {
		return rf(ctx, orgID, snapshotUUID, isLatest)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) string); ok {
		r0 = rf(ctx, orgID, snapshotUUID, isLatest)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, bool) error); ok {
		r1 = rf(ctx, orgID, snapshotUUID, isLatest)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields: ctx, orgID, repoConfigUuid, paginationData, filterData
func (_m *MockSnapshotDao) List(ctx context.Context, orgID string, repoConfigUuid string, paginationData api.PaginationData, filterData api.FilterData) (api.SnapshotCollectionResponse, int64, error) {
	ret := _m.Called(ctx, orgID, repoConfigUuid, paginationData, filterData)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 api.SnapshotCollectionResponse
	var r1 int64
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, api.PaginationData, api.FilterData) (api.SnapshotCollectionResponse, int64, error)); ok {
		return rf(ctx, orgID, repoConfigUuid, paginationData, filterData)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, api.PaginationData, api.FilterData) api.SnapshotCollectionResponse); ok {
		r0 = rf(ctx, orgID, repoConfigUuid, paginationData, filterData)
	} else {
		r0 = ret.Get(0).(api.SnapshotCollectionResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, api.PaginationData, api.FilterData) int64); ok {
		r1 = rf(ctx, orgID, repoConfigUuid, paginationData, filterData)
	} else {
		r1 = ret.Get(1).(int64)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, api.PaginationData, api.FilterData) error); ok {
		r2 = rf(ctx, orgID, repoConfigUuid, paginationData, filterData)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ListByTemplate provides a mock function with given fields: ctx, orgID, template, repositorySearch, paginationData
func (_m *MockSnapshotDao) ListByTemplate(ctx context.Context, orgID string, template api.TemplateResponse, repositorySearch string, paginationData api.PaginationData) (api.SnapshotCollectionResponse, int64, error) {
	ret := _m.Called(ctx, orgID, template, repositorySearch, paginationData)

	if len(ret) == 0 {
		panic("no return value specified for ListByTemplate")
	}

	var r0 api.SnapshotCollectionResponse
	var r1 int64
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, api.TemplateResponse, string, api.PaginationData) (api.SnapshotCollectionResponse, int64, error)); ok {
		return rf(ctx, orgID, template, repositorySearch, paginationData)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, api.TemplateResponse, string, api.PaginationData) api.SnapshotCollectionResponse); ok {
		r0 = rf(ctx, orgID, template, repositorySearch, paginationData)
	} else {
		r0 = ret.Get(0).(api.SnapshotCollectionResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, api.TemplateResponse, string, api.PaginationData) int64); ok {
		r1 = rf(ctx, orgID, template, repositorySearch, paginationData)
	} else {
		r1 = ret.Get(1).(int64)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, api.TemplateResponse, string, api.PaginationData) error); ok {
		r2 = rf(ctx, orgID, template, repositorySearch, paginationData)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// SoftDelete provides a mock function with given fields: ctx, snapUUID
func (_m *MockSnapshotDao) SoftDelete(ctx context.Context, snapUUID string) error {
	ret := _m.Called(ctx, snapUUID)

	if len(ret) == 0 {
		panic("no return value specified for SoftDelete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, snapUUID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewMockSnapshotDao creates a new instance of MockSnapshotDao. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSnapshotDao(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSnapshotDao {
	mock := &MockSnapshotDao{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
