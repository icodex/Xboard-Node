package kernel

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestUserDiff(t *testing.T) {
	tests := []struct {
		name               string
		oldUsers, newUsers []model.UserSpec
		wantAdd            []model.UserSpec
		wantRemove         []model.UserSpec
	}{
		{
			name:      "no change",
			oldUsers:  []model.UserSpec{{ID: 1, UUID: "a"}},
			newUsers:  []model.UserSpec{{ID: 1, UUID: "a"}},
			wantAdd:   nil,
			wantRemove: nil,
		},
		{
			name:      "pure add",
			oldUsers:  []model.UserSpec{{ID: 1, UUID: "a"}},
			newUsers:  []model.UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}},
			wantAdd:   []model.UserSpec{{ID: 2, UUID: "b"}},
			wantRemove: nil,
		},
		{
			name:      "pure remove",
			oldUsers:  []model.UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}},
			newUsers:  []model.UserSpec{{ID: 1, UUID: "a"}},
			wantAdd:   nil,
			wantRemove: []model.UserSpec{{ID: 2, UUID: "b"}},
		},
		{
			// Same ID with a rotated UUID must remove the old credential too,
			// or UserManager backends reject the add (email already exists).
			name:      "uuid rotation",
			oldUsers:  []model.UserSpec{{ID: 1, UUID: "old"}},
			newUsers:  []model.UserSpec{{ID: 1, UUID: "new"}},
			wantAdd:   []model.UserSpec{{ID: 1, UUID: "new"}},
			wantRemove: []model.UserSpec{{ID: 1, UUID: "old"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAdd, gotRemove := UserDiff(tt.oldUsers, tt.newUsers)
			if !reflect.DeepEqual(gotAdd, tt.wantAdd) {
				t.Errorf("toAdd = %v, want %v", gotAdd, tt.wantAdd)
			}
			if !reflect.DeepEqual(gotRemove, tt.wantRemove) {
				t.Errorf("toRemove = %v, want %v", gotRemove, tt.wantRemove)
			}
		})
	}
}
