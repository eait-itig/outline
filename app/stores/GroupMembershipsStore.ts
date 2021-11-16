import invariant from "invariant";
import { filter } from "lodash";
import { action, runInAction } from "mobx";
import GroupMembership from "models/GroupMembership";
import BaseStore from "./BaseStore";
import RootStore from "./RootStore";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'types' or its corresponding ty... Remove this comment to see the full error message
import { PaginationParams } from "types";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'utils/ApiClient' or its corres... Remove this comment to see the full error message
import { client } from "utils/ApiClient";

export default class GroupMembershipsStore extends BaseStore<GroupMembership> {
  // @ts-expect-error ts-migrate(2416) FIXME: Property 'actions' in type 'GroupMembershipsStore'... Remove this comment to see the full error message
  actions = ["create", "delete"];

  constructor(rootStore: RootStore) {
    super(rootStore, GroupMembership);
  }

  @action
  fetchPage = async (
    params: PaginationParams | null | undefined
  ): Promise<any> => {
    this.isFetching = true;

    try {
      const res = await client.post(`/groups.memberships`, params);
      invariant(res && res.data, "Data not available");
      runInAction(`GroupMembershipsStore#fetchPage`, () => {
        res.data.users.forEach(this.rootStore.users.add);
        res.data.groupMemberships.forEach(this.add);
        this.isLoaded = true;
      });
      return res.data.users;
    } finally {
      this.isFetching = false;
    }
  };

  @action
  // @ts-expect-error ts-migrate(2416) FIXME: Property 'create' in type 'GroupMembershipsStore' ... Remove this comment to see the full error message
  async create({ groupId, userId }: { groupId: string; userId: string }) {
    const res = await client.post("/groups.add_user", {
      id: groupId,
      userId,
    });
    invariant(res && res.data, "Group Membership data should be available");
    res.data.users.forEach(this.rootStore.users.add);
    res.data.groups.forEach(this.rootStore.groups.add);
    res.data.groupMemberships.forEach(this.add);
  }

  @action
  async delete({ groupId, userId }: { groupId: string; userId: string }) {
    const res = await client.post("/groups.remove_user", {
      id: groupId,
      userId,
    });
    invariant(res && res.data, "Group Membership data should be available");
    this.remove(`${userId}-${groupId}`);
    runInAction(`GroupMembershipsStore#delete`, () => {
      res.data.groups.forEach(this.rootStore.groups.add);
      this.isLoaded = true;
    });
  }

  @action
  removeGroupMemberships = (groupId: string) => {
    this.data.forEach((_, key) => {
      if (key.includes(groupId)) {
        this.remove(key);
      }
    });
  };

  inGroup = (groupId: string) => {
    return filter(this.orderedData, (member) => member.groupId === groupId);
  };
}