// Code generated by mockery. DO NOT EDIT.

package dao

import (
	context "context"

	api "github.com/content-services/content-sources-backend/pkg/api"

	mock "github.com/stretchr/testify/mock"

	yum "github.com/content-services/yummy/pkg/yum"
)

// MockModuleStreamDao is an autogenerated mock type for the ModuleStreamDao type
type MockModuleStreamDao struct {
	mock.Mock
}

// InsertForRepository provides a mock function with given fields: ctx, repoUuid, pkgGroups
func (_m *MockModuleStreamDao) InsertForRepository(ctx context.Context, repoUuid string, pkgGroups []yum.ModuleMD) (int64, error) {
	ret := _m.Called(ctx, repoUuid, pkgGroups)

	if len(ret) == 0 {
		panic("no return value specified for InsertForRepository")
	}

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []yum.ModuleMD) (int64, error)); ok {
		return rf(ctx, repoUuid, pkgGroups)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []yum.ModuleMD) int64); ok {
		r0 = rf(ctx, repoUuid, pkgGroups)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []yum.ModuleMD) error); ok {
		r1 = rf(ctx, repoUuid, pkgGroups)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// OrphanCleanup provides a mock function with given fields: ctx
func (_m *MockModuleStreamDao) OrphanCleanup(ctx context.Context) error {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for OrphanCleanup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SearchRepositoryModuleStreams provides a mock function with given fields: ctx, orgID, request
func (_m *MockModuleStreamDao) SearchRepositoryModuleStreams(ctx context.Context, orgID string, request api.SearchModuleStreamsRequest) ([]api.SearchModuleStreams, error) {
	ret := _m.Called(ctx, orgID, request)

	if len(ret) == 0 {
		panic("no return value specified for SearchRepositoryModuleStreams")
	}

	var r0 []api.SearchModuleStreams
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, api.SearchModuleStreamsRequest) ([]api.SearchModuleStreams, error)); ok {
		return rf(ctx, orgID, request)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, api.SearchModuleStreamsRequest) []api.SearchModuleStreams); ok {
		r0 = rf(ctx, orgID, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.SearchModuleStreams)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, api.SearchModuleStreamsRequest) error); ok {
		r1 = rf(ctx, orgID, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SearchSnapshotModuleStreams provides a mock function with given fields: ctx, orgID, request
func (_m *MockModuleStreamDao) SearchSnapshotModuleStreams(ctx context.Context, orgID string, request api.SearchSnapshotModuleStreamsRequest) ([]api.SearchModuleStreams, error) {
	ret := _m.Called(ctx, orgID, request)

	if len(ret) == 0 {
		panic("no return value specified for SearchSnapshotModuleStreams")
	}

	var r0 []api.SearchModuleStreams
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, api.SearchSnapshotModuleStreamsRequest) ([]api.SearchModuleStreams, error)); ok {
		return rf(ctx, orgID, request)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, api.SearchSnapshotModuleStreamsRequest) []api.SearchModuleStreams); ok {
		r0 = rf(ctx, orgID, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.SearchModuleStreams)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, api.SearchSnapshotModuleStreamsRequest) error); ok {
		r1 = rf(ctx, orgID, request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewMockModuleStreamDao creates a new instance of MockModuleStreamDao. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockModuleStreamDao(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockModuleStreamDao {
	mock := &MockModuleStreamDao{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
