import { observer } from "mobx-react";
import * as React from "react";
import { useTranslation } from "react-i18next";
import FilterOptions from "components/FilterOptions";
import useStores from "hooks/useStores";

type Props = {
  userId: string | null | undefined;
  onSelect: (key: string | null | undefined) => void;
};

function UserFilter(props: Props) {
  const { onSelect, userId } = props;
  const { t } = useTranslation();
  const { users } = useStores();
  React.useEffect(() => {
    users.fetchPage({
      limit: 100,
    });
  }, [users]);
  const options = React.useMemo(() => {
    // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'user' implicitly has an 'any' type.
    const userOptions = users.all.map((user) => ({
      key: user.id,
      label: user.name,
    }));
    return [
      {
        key: "",
        label: t("Any author"),
      },
      ...userOptions,
    ];
  }, [users.all, t]);
  return (
    <FilterOptions
      options={options}
      activeKey={userId}
      onSelect={onSelect}
      defaultLabel={t("Any author")}
      selectedPrefix={`${t("Author")}:`}
    />
  );
}

export default observer(UserFilter);