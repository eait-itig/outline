// @ts-expect-error ts-migrate(7016) FIXME: Could not find a declaration file for module '@out... Remove this comment to see the full error message
import passport from "@outlinewiki/koa-passport";
import { addMonths } from "date-fns";
import Koa from "koa";
import bodyParser from "koa-body";
import Router from "koa-router";
import { AuthenticationError } from "../../errors";
import auth from "../../middlewares/authentication";
import validation from "../../middlewares/validation";
import { Collection, Team, View } from "../../models";
// @ts-expect-error ts-migrate(7034) FIXME: Variable 'providers' implicitly has type 'any[]' i... Remove this comment to see the full error message
import providers from "./providers";

const app = new Koa();
const router = new Router();
router.use(passport.initialize());
// dynamically load available authentication provider routes
// @ts-expect-error ts-migrate(7005) FIXME: Variable 'providers' implicitly has an 'any[]' typ... Remove this comment to see the full error message
providers.forEach((provider) => {
  if (provider.enabled) {
    router.use("/", provider.router.routes());
  }
});
router.get("/redirect", auth(), async (ctx) => {
  const user = ctx.state.user;
  const jwtToken = user.getJwtToken();

  if (jwtToken === ctx.params.token) {
    // @ts-expect-error ts-migrate(7009) FIXME: 'new' expression, whose target lacks a construct s... Remove this comment to see the full error message
    throw new AuthenticationError("Cannot extend token");
  }

  // ensure that the lastActiveAt on user is updated to prevent replay requests
  await user.updateActiveAt(ctx.request.ip, true);
  ctx.cookies.set("accessToken", jwtToken, {
    httpOnly: false,
    expires: addMonths(new Date(), 3),
  });
  const [team, collection, view] = await Promise.all([
    Team.findByPk(user.teamId),
    Collection.findFirstCollectionForUser(user),
    View.findOne({
      where: {
        userId: user.id,
      },
    }),
  ]);
  const hasViewedDocuments = !!view;
  ctx.redirect(
    !hasViewedDocuments && collection
      ? `${team.url}${collection.url}`
      : `${team.url}/home`
  );
});
app.use(bodyParser());
app.use(validation());
app.use(router.routes());

export default app;