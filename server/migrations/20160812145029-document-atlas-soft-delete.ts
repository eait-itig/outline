module.exports = {
  // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'queryInterface' implicitly has an 'any'... Remove this comment to see the full error message
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn("atlases", "deletedAt", {
      type: Sequelize.DATE,
      allowNull: true,
    });
    await queryInterface.addColumn("documents", "deletedAt", {
      type: Sequelize.DATE,
      allowNull: true,
    });
  },
  // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'queryInterface' implicitly has an 'any'... Remove this comment to see the full error message
  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn("atlases", "deletedAt");
    await queryInterface.removeColumn("documents", "deletedAt");
  },
};