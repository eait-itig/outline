import { observer } from "mobx-react";
import * as React from "react";
import { useTranslation, Trans } from "react-i18next";
import Group from "models/Group";
import GroupMembers from "scenes/GroupMembers";
import Button from "components/Button";
import Flex from "components/Flex";
import HelpText from "components/HelpText";
import Input from "components/Input";
import Modal from "components/Modal";
import useStores from "hooks/useStores";
import useToasts from "hooks/useToasts";

type Props = {
  onSubmit: () => void;
};

function GroupNew({ onSubmit }: Props) {
  const { groups } = useStores();
  const { t } = useTranslation();
  const { showToast } = useToasts();
  const [name, setName] = React.useState();
  const [isSaving, setIsSaving] = React.useState();
  const [group, setGroup] = React.useState();

  const handleSubmit = async (ev: React.SyntheticEvent) => {
    ev.preventDefault();
    // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'true' is not assignable to param... Remove this comment to see the full error message
    setIsSaving(true);
    const group = new Group(
      {
        name: name,
      },
      groups
    );

    try {
      // @ts-expect-error ts-migrate(2554) FIXME: Expected 1 arguments, but got 0.
      setGroup(await group.save());
    } catch (err) {
      showToast(err.message, {
        type: "error",
      });
    } finally {
      // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'false' is not assignable to para... Remove this comment to see the full error message
      setIsSaving(false);
    }
  };

  const handleNameChange = (ev: React.SyntheticEvent<any>) => {
    // @ts-expect-error ts-migrate(2339) FIXME: Property 'value' does not exist on type 'EventTarg... Remove this comment to see the full error message
    setName(ev.target.value);
  };

  return (
    <>
      <form onSubmit={handleSubmit}>
        <HelpText>
          <Trans>
            Groups are for organizing your team. They work best when centered
            around a function or a responsibility — Support or Engineering for
            example.
          </Trans>
        </HelpText>
        <Flex>
          <Input
            type="text"
            label="Name"
            onChange={handleNameChange}
            value={name}
            required
            autoFocus
            flex
          />
        </Flex>
        <HelpText>
          <Trans>You’ll be able to add people to the group next.</Trans>
        </HelpText>

        <Button type="submit" disabled={isSaving || !name}>
          // @ts-expect-error ts-migrate(2322) FIXME: Type 'string |
          HTMLCollection' is not assignable t... Remove this comment to see the
          full error message
          {isSaving ? `${t("Creating")}…` : t("Continue")}
        </Button>
      </form>
      <Modal
        title={t("Group members")}
        onRequestClose={onSubmit}
        isOpen={!!group}
      >
        <GroupMembers group={group} />
      </Modal>
    </>
  );
}

export default observer(GroupNew);